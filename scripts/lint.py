#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lint.py —— Python 语法检查（等价 `python -m py_compile`，但**不写字节码缓存**）。

为什么不用 py_compile / compileall：它们会写 `__pycache__/*.pyc`，在受限环境
（只读挂载、平台沙箱禁止文件替换/删除）会报 `Operation not permitted` 而**误报语法失败**。
这里用内置 `compile()` 只做语法校验，零文件系统副作用。

用法：`make lint`
退出码：0=全部通过；1=有语法错误。
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGETS = [
    "services/portal", "services/correlator", "services/soar", "services/common",
    "services/stream", "services/ingest-adapter", "scripts",
]

bad = []
n = 0
for rel in TARGETS:
    d = ROOT / rel
    if not d.is_dir():
        continue
    for f in sorted(d.glob("*.py")):
        n += 1
        try:
            compile(f.read_text(encoding="utf-8"), str(f), "exec")
        except SyntaxError as e:
            bad.append(f"{f.relative_to(ROOT)}:{e.lineno}: {e.msg}")
        except UnicodeDecodeError as e:
            bad.append(f"{f.relative_to(ROOT)}: 编码错误 {e}")

for b in bad:
    print(f"  ✘ {b}")
print(f"Python 语法检查：{n - len(bad)}/{n} 通过"
      + ("" if not bad else f"，{len(bad)} 个文件有语法错误"))
sys.exit(1 if bad else 0)
