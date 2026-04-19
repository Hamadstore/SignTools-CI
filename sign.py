#!/usr/bin/env python3

import json
import os
import plistlib
import random
import shutil
import string
import subprocess
import tempfile
from pathlib import Path
from typing import Any, IO, List, Mapping, Optional, Tuple, Union

StrPath = Union[str, Path]


def decode_clean(data: Optional[bytes]) -> str:
	return data.decode("utf-8", errors="replace").strip() if data else ""


def print_object(obj: Any) -> None:
	print(json.dumps(obj, indent=4, sort_keys=True, default=str))


def safe_glob(base: Path, pattern: str):
	for path in sorted(base.glob(pattern)):
		if path.name.startswith("._"):
			continue
		if path.name in {".DS_Store", ".AppleDouble", "__MACOSX"}:
			continue
		yield path


def read_file(file_path: StrPath) -> str:
	return Path(file_path).read_text(encoding="utf-8").strip()


def write_file(file_path: StrPath, content: str) -> None:
	Path(file_path).write_text(content, encoding="utf-8")


def run_process(
	*cmd: str,
	capture: bool = True,
	check: bool = True,
	env: Optional[Mapping[str, str]] = None,
	cwd: Optional[str] = None,
	timeout: Optional[float] = None,
) -> subprocess.CompletedProcess[bytes]:
	try:
		return subprocess.run(
			cmd,
			capture_output=capture,
			check=check,
			env=env,
			cwd=cwd,
			timeout=timeout,
		)
	except subprocess.CalledProcessError as e:
		raise RuntimeError(
			json.dumps(
				{
					"cmd": list(cmd),
					"returncode": e.returncode,
					"stdout": decode_clean(e.stdout),
					"stderr": decode_clean(e.stderr),
				},
				indent=2,
			)
		) from e
	except subprocess.TimeoutExpired as e:
		raise RuntimeError(
			json.dumps(
				{
					"cmd": list(cmd),
					"timeout": timeout,
					"stdout": decode_clean(e.stdout),
					"stderr": decode_clean(e.stderr),
				},
				indent=2,
			)
		) from e


def run_process_async(
	*cmd: str,
	env: Optional[Mapping[str, str]] = None,
	cwd: Optional[str] = None,
) -> subprocess.Popen[bytes]:
	return subprocess.Popen(
		cmd,
		env=env,
		cwd=cwd,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
	)


def popen_check(pipe: subprocess.Popen[bytes]) -> None:
	if pipe.returncode != 0:
		stdout, stderr = pipe.communicate()
		raise RuntimeError(
			json.dumps(
				{
					"message": f"{pipe.args} failed with status code {pipe.returncode}",
					"stdout": decode_clean(stdout),
					"stderr": decode_clean(stderr),
				},
				indent=2,
			)
		)


def rand_str(length: int, seed: Any = None) -> str:
	old_state = None
	if seed is not None:
		old_state = random.getstate()
		random.seed(seed)
	try:
		return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
	finally:
		if old_state is not None:
			random.setstate(old_state)


def extract_zip(archive: Path, dest_dir: Path):
	dest_dir.mkdir(parents=True, exist_ok=True)
	return run_process("unzip", "-o", str(archive), "-d", str(dest_dir))


def archive_zip(content_dir: Path, dest_file: Path):
	if dest_file.exists():
		dest_file.unlink()
	return run_process("zip", "-qr", str(dest_file.resolve()), ".", cwd=str(content_dir))


def extract_tar(archive: Path, dest_dir: Path):
	dest_dir.mkdir(parents=True, exist_ok=True)
	return run_process("tar", "-xf", str(archive), "-C", str(dest_dir))


def move_merge_replace(src: Path, dest_dir: Path) -> None:
	dest_dir.mkdir(parents=True, exist_ok=True)
	dest = dest_dir / src.name

	if src.resolve() == dest.resolve():
		return

	if src.is_dir():
		shutil.copytree(src, dest, dirs_exist_ok=True)
		shutil.rmtree(src)
	else:
		shutil.copy2(src, dest)
		src.unlink()


def plutil_convert(plist: Path) -> bytes:
	return run_process("plutil", "-convert", "xml1", "-o", "-", str(plist)).stdout


def plist_load(plist: Path) -> Any:
	return plistlib.loads(plutil_convert(plist))


def plist_loads(plist_text: str) -> Any:
	with tempfile.NamedTemporaryFile(suffix=".plist", mode="w", encoding="utf-8", delete=True) as f:
		f.write(plist_text)
		f.flush()
		return plist_load(Path(f.name))


def plist_dump(data: Any, f: IO[bytes]) -> None:
	plistlib.dump(data, f)


def file_is_type(file: Path, file_type: str) -> bool:
	return file_type in decode_clean(run_process("file", str(file)).stdout)


def get_info_plist_path(app_dir: Path) -> Path:
	items = list(safe_glob(app_dir, "**/Info.plist"))
	if not items:
		raise FileNotFoundError(f"No Info.plist found in {app_dir}")
	return min(items, key=lambda p: len(str(p)))


def get_main_app_path(app_dir: Path) -> Path:
	items = list(safe_glob(app_dir, "**/*.app"))
	if not items:
		raise FileNotFoundError(f"No .app found in {app_dir}")
	return min(items, key=lambda p: len(str(p)))


def curl_with_auth(
	url: str,
	token: str,
	form_data: Optional[List[Tuple[str, str]]] = None,
	output: Optional[Path] = None,
	check: bool = True,
	capture: bool = True,
):
	form_data = form_data or []
	args: List[str] = []
	for key, value in form_data:
		args.extend(["-F", f"{key}={value}"])
	if output:
		args.extend(["-o", str(output)])

	return run_process(
		"curl",
		"-S",
		"-f",
		"-L",
		"-H",
		f"Authorization: Bearer {token}",
		*args,
		url,
		check=check,
		capture=capture,
	)
