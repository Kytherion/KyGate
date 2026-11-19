"""Model packs: the Guard's optional second level.

A pack is a directory holding a manifest, `pack.json`, and the files it names.
The manifest says what the pack does (its task and runtime), where each file
comes from (a download address at a pinned revision), the SHA-256 of each
file, its license and sources, its languages, and how the model's labels map
to KyGate's data types.

Rules:
- Nothing is downloaded except by `kygate-guard models pull`, which shows the
  pack's models, size, and license and asks before downloading.
- Every file is checked against its SHA-256 when it is downloaded, and again
  when the Guard loads the pack. A pack that does not match is not used.
- Several packs can be installed; the Guard loads them all.

    kygate-guard models list
    kygate-guard models pull personal-data [--yes]
    kygate-guard models add PATH/pack.json [--yes]      # a pack described by its own manifest
    kygate-guard models remove NAME
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import urllib.request
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

MANIFEST = "pack.json"
FORMAT = 1
RUNTIMES = {"onnx-token-classifier", "onnx-sequence-classifier"}


class PackError(Exception):
    pass


@dataclass
class PackFile:
    path: str
    url: str
    size: int
    sha256: str


@dataclass
class Pack:
    name: str
    title: str
    task: str
    runtime: str
    version: str
    source: str
    license: str
    languages: list[str]
    notice: str
    files: list[PackFile]
    labels: str
    label_map: dict[str, str]
    settings: dict = field(default_factory=dict)
    # For a classifier of threats: which of its labels is which threat, such as
    # {"INJECTION": "PROMPT_INJECTION"}.
    threat_map: dict[str, str] = field(default_factory=dict)
    dir: Path | None = None

    @property
    def total_size(self) -> int:
        return sum(f.size for f in self.files)

    def file(self, path: str) -> Path:
        assert self.dir is not None
        return self.dir / path


def parse(data: dict) -> Pack:
    """Checks a manifest and returns the pack it describes."""
    def need(key, kind=str):
        v = data.get(key)
        if not isinstance(v, kind) or (kind is str and not v.strip()):
            raise PackError(f"pack manifest: '{key}' is missing or not a {kind.__name__}")
        return v
    if data.get("format") != FORMAT:
        raise PackError(f"pack manifest: format {data.get('format')!r} is not supported (this Guard reads format {FORMAT})")
    name = need("name")
    if not name.replace("-", "").replace("_", "").isalnum():
        raise PackError(f"pack manifest: name {name!r} must be letters, digits, '-' and '_' only")
    runtime = need("runtime")
    if runtime not in RUNTIMES:
        raise PackError(f"pack {name}: runtime {runtime!r} is not one this Guard has ({', '.join(sorted(RUNTIMES))})")
    files = []
    for f in need("files", list):
        p = str(f.get("path", ""))
        if not p or p.startswith(("/", "\\")) or ".." in Path(p).parts:
            raise PackError(f"pack {name}: file path {p!r} must be relative and stay inside the pack")
        sha = str(f.get("sha256", "")).lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise PackError(f"pack {name}: file {p} needs a SHA-256 (64 hex digits)")
        url = str(f.get("url", ""))
        if url and not url.startswith("https://"):
            raise PackError(f"pack {name}: file {p} must be downloaded over https")
        files.append(PackFile(p, url, int(f.get("size", 0)), sha))
    label_map = need("label_map", dict)
    return Pack(name=name, title=need("title"), task=need("task"), runtime=runtime, version=need("version"),
                source=data.get("source", ""), license=need("license"), languages=list(data.get("languages", [])),
                notice=data.get("notice", ""), files=files, labels=need("labels"),
                label_map={str(k): str(v) for k, v in label_map.items()}, settings=dict(data.get("settings", {})),
                threat_map={str(k): str(v).upper() for k, v in dict(data.get("threat_map", {})).items()})


def catalog() -> dict[str, dict]:
    """The packs this version of the Guard knows by name."""
    out = {}
    for entry in resources.files("kygate_guard.catalog").iterdir():
        if entry.name.endswith(".json"):
            data = json.loads(entry.read_text(encoding="utf-8"))
            out[data["name"]] = data
    return out


def default_pack(known: dict[str, dict] | None = None) -> str:
    """The one pack 'kygate-guard models pull' installs when no name is given.
    Every other catalog pack is an add-on."""
    known = catalog() if known is None else known
    names = sorted(n for n, d in known.items() if d.get("default") is True)
    if len(names) != 1:
        raise PackError(f"the catalog must mark exactly one pack as the default, not {names}")
    return names[0]


def default_dir() -> Path:
    if v := os.environ.get("KYGATE_GUARD_MODELS"):
        return Path(v)
    return Path.home() / ".kygate" / "models"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(pack_dir: Path, verify: bool = True) -> Pack:
    """Reads an installed pack, and checks its files against their SHA-256."""
    try:
        data = json.loads((pack_dir / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise PackError(f"{pack_dir}: cannot read {MANIFEST}: {e}") from e
    pack = parse(data)
    pack.dir = pack_dir
    if verify:
        for f in pack.files:
            p = pack.file(f.path)
            if not p.is_file():
                raise PackError(f"pack {pack.name}: {f.path} is missing; run 'kygate-guard models pull {pack.name}' again")
            if sha256_of(p) != f.sha256:
                raise PackError(f"pack {pack.name}: {f.path} does not match its SHA-256; it was changed or damaged. Run 'kygate-guard models pull {pack.name}' again")
    return pack


def installed(models_dir: Path, verify: bool = True) -> tuple[list[Pack], list[str]]:
    """Every installed pack, and an error for each one that cannot be used."""
    packs, errors = [], []
    if not models_dir.is_dir():
        return packs, errors
    for d in sorted(models_dir.iterdir()):
        if (d / MANIFEST).is_file():
            try:
                packs.append(load(d, verify))
            except PackError as e:
                errors.append(str(e))
    return packs, errors


def _mb(n: int) -> str:
    return f"{n / 1e6:,.0f} MB" if n >= 1e6 else f"{n / 1e3:,.0f} kB"


def install(data: dict, models_dir: Path, assume_yes: bool = False, out=sys.stdout, ask=input) -> Pack:
    """Shows the pack, asks, downloads its files, checks each SHA-256, and
    installs the pack. The manifest is written last, so a pack whose download
    was interrupted is never loaded."""
    pack = parse(data)
    dest = models_dir / pack.name
    print(f"{pack.title}\n  pack      {pack.name}, version {pack.version}\n  source    {pack.source}\n  license   {pack.license}"
          f"\n  size      {_mb(pack.total_size)} in {len(pack.files)} files\n  languages {', '.join(pack.languages) or '-'}", file=out)
    if pack.notice:
        print(f"  notice    {pack.notice}", file=out)
    try:
        current = load(dest)
        if current.version == pack.version:
            print(f"\nAlready installed in {dest}, and its files match.", file=out)
            return current
    except PackError:
        pass
    if not assume_yes:
        answer = ask(f"\nDownload {_mb(pack.total_size)} into {dest}? [y/N] ").strip().lower()
        if answer not in ("y", "yes", "o", "oui"):
            raise PackError("nothing was downloaded")
    tmp = models_dir / f".{pack.name}.partial"
    tmp.mkdir(parents=True, exist_ok=True)
    for f in pack.files:
        target = tmp / f.path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file() and sha256_of(target) == f.sha256:
            print(f"  {f.path}: already downloaded", file=out)
            continue
        if not f.url:
            raise PackError(f"pack {pack.name}: {f.path} has no download address; copy it into {tmp} and run the command again")
        _download(f, target, out)
    if dest.exists():
        shutil.rmtree(dest)
    tmp.rename(dest)
    (dest / MANIFEST).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    pack = load(dest)
    print(f"\nInstalled {pack.name} in {dest}. Restart the Guard to use it.", file=out)
    return pack


def _download(f: PackFile, target: Path, out) -> None:
    req = urllib.request.Request(f.url, headers={"User-Agent": "kygate-guard"})
    h = hashlib.sha256()
    part = target.with_suffix(target.suffix + ".download")
    done, last = 0, -1
    with urllib.request.urlopen(req, timeout=60) as r, open(part, "wb") as w:
        while chunk := r.read(1 << 20):
            w.write(chunk)
            h.update(chunk)
            done += len(chunk)
            pct = int(done * 100 / f.size) if f.size else 0
            if pct // 10 != last:
                last = pct // 10
                print(f"  {f.path}: {pct}% of {_mb(f.size)}", file=out, flush=True)
    if h.hexdigest() != f.sha256:
        part.unlink(missing_ok=True)
        raise PackError(f"{f.path}: the downloaded file does not match its SHA-256 (got {h.hexdigest()}); nothing was installed")
    part.replace(target)


def remove(name: str, models_dir: Path) -> None:
    d = models_dir / name
    if not (d / MANIFEST).is_file():
        raise PackError(f"no pack named {name!r} in {models_dir}")
    shutil.rmtree(d)


def cli(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="kygate-guard models", description="Manage the Guard's model packs. Nothing is downloaded without this command.")
    p.add_argument("--models", default=str(default_dir()), help="model directory (default: KYGATE_GUARD_MODELS, or ~/.kygate/models)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="installed packs, and those this Guard knows by name")
    pull = sub.add_parser("pull", help="download a pack this Guard knows by name; with no name, the default pack")
    pull.add_argument("name", nargs="?", help="the pack; without it, the default pack (see 'models list')")
    pull.add_argument("--yes", action="store_true", help="do not ask before downloading")
    add = sub.add_parser("add", help="install a pack described by its own manifest")
    add.add_argument("manifest")
    add.add_argument("--yes", action="store_true")
    rm = sub.add_parser("remove", help="delete an installed pack")
    rm.add_argument("name")
    args = p.parse_args(argv)
    models_dir = Path(args.models)
    try:
        if args.cmd == "list":
            packs, errors = installed(models_dir)
            known = catalog()
            default = default_pack(known)

            def role(name: str) -> str:
                return "default" if name == default else ("add-on" if name in known else "your own")

            print(f"Model directory: {models_dir}")
            for pk in packs:
                print(f"  {pk.name:16} installed  {role(pk.name):8} {pk.title}, {pk.license}, version {pk.version[:12]}, {_mb(pk.total_size)}")
            for e in errors:
                print(f"  unusable: {e}")
            names = {pk.name for pk in packs}
            for name, data in sorted(known.items(), key=lambda kv: (kv[0] != default, kv[0])):
                if name not in names:
                    size = sum(int(f.get("size", 0)) for f in data.get("files", []))
                    how = "kygate-guard models pull" if name == default else f"kygate-guard models pull {name}"
                    print(f"  {name:16} available  {role(name):8} {data['title']}, {data['license']}, {_mb(size)} ({how})")
        elif args.cmd == "pull":
            known = catalog()
            if args.name is None:
                args.name = default_pack(known)
            if args.name not in known:
                raise PackError(f"this Guard knows no pack named {args.name!r}; known: {', '.join(sorted(known))}. For another model, write a manifest and use 'models add'")
            install(known[args.name], models_dir, args.yes)
        elif args.cmd == "add":
            data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            install(data, models_dir, args.yes)
        elif args.cmd == "remove":
            remove(args.name, models_dir)
            print(f"Removed {args.name}. Restart the Guard.")
    except (PackError, OSError, ValueError) as e:
        print(f"kygate-guard models: {e}", file=sys.stderr)
        return 1
    return 0
