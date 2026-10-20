# 第三方软件与研究来源

PFDAM为本团队自主研究方案，论文作者为团队成员，DOI 10.1109/JIOT.2024.3356593；论文用于解释前期研究。OpenSSL、mcl及其他第三方组件按原许可署名，引用37具体参数论证仍待独立审查。

mcl v3.08，提交 a8cad811f720264e6e140f54c66463be60189789，BSD-3-Clause；原始 COPYRIGHT 和对应源码随包保留。OpenSSL3.5.5、GMP及C/C++运行库动态使用宿主安装，不随包复制系统二进制。OpenSSL 项目采用 Apache-2.0；系统组件以各自许可为准。

Python wheels 与前端依赖的原始许可证/NOTICE 摘录至 software/licenses。gmpy2 2.2.1 按 LGPL-3.0-or-later 提供原始 sdist、构建脚本及可替换的动态扩展；其他依赖按其实际元数据和随附原文处理。字体使用系统字体，不打包字体文件。

| 生态 | 包 | 版本 | 元数据许可 |
|---|---|---|---|
| python | annotated-doc | 0.0.5 | MIT |
| python | annotated-types | 0.8.0 | MIT |
| python | anyio | 4.15.1 | MIT |
| python | attrs | 26.1.0 | MIT |
| python | certifi | 2026.7.22 | MPL-2.0 |
| python | click | 8.5.0 | BSD-3-Clause |
| python | fastapi | 0.135.1 | MIT |
| python | gmpy2 | 2.2.1 | LGPL-3.0+ |
| python | h11 | 0.16.0 | MIT |
| python | httpcore | 1.0.9 | BSD-3-Clause |
| python | httpx | 0.28.1 | BSD-3-Clause |
| python | idna | 3.20 | BSD-3-Clause |
| python | iniconfig | 2.3.1 | MIT |
| python | jcs | 0.2.1 | Apache-2.0 |
| python | jsonschema | 4.26.0 | MIT |
| python | jsonschema-specifications | 2025.9.1 | MIT |
| python | packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| python | pluggy | 1.7.0 | MIT |
| python | pydantic | 2.14.1 | MIT |
| python | pydantic_core | 2.50.1 | MIT |
| python | Pygments | 2.21.0 | BSD-2-Clause |
| python | pytest | 9.0.2 | MIT |
| python | referencing | 0.37.0 | MIT |
| python | rpds-py | 2026.9.1 | MIT |
| python | starlette | 1.8.0 | BSD-3-Clause |
| python | typing_extensions | 4.16.0 | PSF-2.0 |
| python | typing-inspection | 0.4.4 | MIT |
| python | uvicorn | 0.42.0 | BSD-3-Clause |
| npm | csstype | 3.2.3 | MIT |
| npm | detect-libc | 2.1.2 | Apache-2.0 |
| npm | fdir | 6.5.0 | MIT |
| npm | lightningcss | 1.33.0 | MPL-2.0 |
| npm | lightningcss-win32-x64-msvc | 1.33.0 | MPL-2.0 |
| npm | nanoid | 3.3.20 | MIT |
| npm | picocolors | 1.1.1 | ISC |
| npm | picomatch | 4.0.7 | MIT |
| npm | playwright | 1.64.1 | Apache-2.0 |
| npm | playwright-core | 1.64.1 | Apache-2.0 |
| npm | postcss | 8.5.30 | MIT |
| npm | react | 19.3.1 | MIT |
| npm | react-dom | 19.3.1 | MIT |
| npm | rolldown | 1.2.14 | MIT |
| npm | scheduler | 0.28.0 | MIT |
| npm | source-map-js | 1.2.2 | BSD-3-Clause |
| npm | tinyglobby | 0.2.17 | MIT |
| npm | typescript | 7.0.2 | Apache-2.0 |
| npm | vite | 8.3.4 | MIT |
| npm | @oxc-project/types | 0.154.0 | MIT |
| npm | @playwright/test | 1.64.1 | Apache-2.0 |
| npm | @rolldown/binding-win32-x64-msvc | 1.2.14 | MIT |
| npm | @rolldown/pluginutils | 1.0.1 | MIT |
| npm | @types/react | 19.3.0 | MIT |
| npm | @types/react-dom | 19.3.0 | MIT |
| npm | @typescript/typescript-win32-x64 | 7.0.2 | Apache-2.0 |
| npm | @vitejs/plugin-react | 6.1.2 | MIT |

元数据摘要用于查阅，许可条款以原始文件为准。项目本身的对外授权由权利人确定；本次仅生成本地审阅与参赛准备包，不自动公开发布。

NIST ACVP-Server官方测试向量固定提交975de31eb83d87039ec88934fdc47d8c312b892d；原始prompt/expectedResults和来源摘要保存在references/crypto-vectors。所选15例组未修改，原始许可全文见NIST_NOTICE.txt。算法和向量来源署名NIST，执行通过不表示NIST认证。
