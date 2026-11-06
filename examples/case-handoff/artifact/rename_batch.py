#!/usr/bin/env python3
"""rename_batch.py —— 批量重命名下载目录里的文件

看起来能用，也跑得通。问题在边界：目录会被改名、重名会覆盖、没有预演。

用法：python rename_batch.py <目录> <前缀>
"""

import glob
import os
import sys


def main(folder: str, prefix: str) -> None:
    files = sorted(glob.glob(os.path.join(folder, "*")))
    for i, path in enumerate(files, 1):
        ext = os.path.splitext(path)[1]
        new = os.path.join(folder, f"{prefix}_{i:03d}{ext}")
        os.rename(path, new)
    print(f"done: {len(files)} files")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
