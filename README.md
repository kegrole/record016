# imgscan

OCI 镜像布局敏感文件分析器。只使用 Python 标准库，无第三方依赖。

镜像由多层叠加而成：早期层里的文件即使被后续层用 whiteout 删掉，仍然
能从历史层的 blob 里完整解出来。imgscan 逐层重放整个镜像，把这类"已删
除但可恢复"的敏感文件、权限问题和 root 运行身份全部翻出来。

## 用法

    python -m imgscan.cli --layout <镜像布局目录> --out <报告路径> [--rules rules.json]

demo：

    python demo/build_layout.py   # 重新生成 demo/layout（确定性构建）
    python -m imgscan.cli --layout demo/layout --out out/report.json

运行后 stdout 打印一行摘要，例如：

    summary: layers=2 final_files=2 findings=4

测试：

    cd tests && python -m unittest test_imgscan -v
    # 或在仓库根目录：python -m unittest discover -s tests -v

## OCI 布局结构

    <layout>/
        oci-layout                 版本标记（可选）
        index.json                 指向 manifest blob 的描述符
        blobs/sha256/<hexdigest>   全部内容寻址 blob：
                                   manifest json、config json、各层 tar/tar+gzip

解析流程（imgscan/layout.py、imgscan/blobs.py）：读 index.json 取第一个
manifest 描述符，按 digest 在 blobs/<algorithm>/<hex> 下找到 manifest，
再按 manifest.config.digest 读 config json。层 blob 可能是纯 tar 或
gzip 压缩 tar，按魔数 1f 8b 自动识别，不依赖 mediaType。

## 层叠与 whiteout 语义

imgscan/layers.py 按 manifest.layers 的顺序逐层应用：

- 普通文件：后层同名文件覆盖前层，记录进历史（FileEntry）。
- 删除标记：层里出现 dir/.wh.name 表示删除下层已有的 dir/name
  （imgscan/whiteout.py）。whiteout 条目本身不进最终文件清单。
- 不透明目录：dir/.wh..wh..opq 表示遮蔽下层该目录下的全部内容。
- 只有真正删掉了下层文件的 whiteout 才记录 DeleteEvent，用于历史层分析。

最终文件清单 = 全部层应用完后存活的常规文件。被 whiteout 删掉的文件
不出现在清单里，但它的历史记录仍在：报告会指出它出现在第几层、在第
几层被删、以及仍可从哪个历史层 blob 取回。

## 敏感规则与权限判定

imgscan/rules.py 内置规则，可用 --rules rules.json 覆盖（JSON 对象，
键与 DEFAULT_RULES 相同，列表整体替换）：

- filename_patterns：basename 的 fnmatch 模式，如 .env、id_rsa、
  *.pem、*.key、.netrc、credentials 等凭据类文件名/扩展名。
- content_keywords：内容关键字（password、token、secret、api_key、
  private key 等），只对 content_scan_names 命中的配置类文件且不超过
  content_scan_max_bytes 的文件扫描。
- 命中文件名或内容任一规则即报 sensitive_file。

权限判定（imgscan/perm.py）：

- world-readable：tar 条目模式位含 other-read（0o004）的敏感文件，
  在 detail 中标注 world-readable，mode 字段给出八进制模式（如 0644）。
- root 运行：config 的 config.User 为空、"0" 或 "root" 时，报
  root_user 发现。

## 报告格式

JSON，顶层三个键：

- findings：每条发现固定六个字段
  - kind：sensitive_file / whiteout_deleted / root_user
  - path：镜像内路径（root_user 为 null）
  - layer_index / layer_digest：发现所在层（root_user 为 null）
  - mode：八进制权限串（非文件类发现为 null）
  - detail：人类可读说明（含 whiteout 删除与可恢复层信息）
- final_files：最终镜像文件清单（排序后的路径列表）
- summary：layers（层数）、final_files（最终文件数）、findings（发现数）

布局自身的文件（index.json、manifest、blobs/ 下的原始 tar）属于
OCI 簿记数据，永远不会被当成镜像内容报告。

## 目录结构

    imgscan/            分析器包
        layout.py       OCI 布局解析（index/manifest/config）
        blobs.py        digest 寻址与 tar/gzip 解包
        layers.py       逐层应用，产出历史与最终文件清单
        whiteout.py     whiteout / opaque 目录语义
        rules.py        可配置的敏感规则
        perm.py         权限位与运行身份判定
        report.py       发现汇总与报告生成
        cli.py          命令行入口
        __main__.py     python -m imgscan 别名
    demo/build_layout.py  demo 布局构造脚本（确定性）
    demo/layout/          构造好的两层 OCI 布局
    tests/test_imgscan.py 判定口径测试
