# 项目事实清单

接管日期：2026-10-15（Asia/Shanghai）。原目录包含设计资料，接管前 `git status` 返回非 Git 仓库。已建立本地 Git 工程；未配置远端，未覆盖原文件。

已找到13页 PFDAM 作者版本，DOI 10.1109/JIOT.2024.3356593。V3 Markdown、Word、三份开发契约、申报表与原型截图均存在。未发现作者源码、V2 HTML、原工作包和 E01—E20 文件。

实施依据采用最新 Agent 手册。V3原始文件保留不改，当前申报类型使用“密码应用技术”。缺失的工作包和扩展测试将按手册重新编制，并标明来源。

执行环境：Windows 主机，WSL Ubuntu x86_64；GNU C/C++、CMake、GMP 开发包、OpenSSL 3.5.5/libssl-dev 已存在。Docker 客户端存在，daemon 未运行。首版采用 WSL 多进程，不依赖 Docker daemon。Python 3.14.4；后端依赖尚待项目级安装。

数据、运行记录、探针和源代码均从接管后开始生成；原设计中的数字不作为实测成绩。
