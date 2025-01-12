# XX加速器

XX加速器是一个专为 Windows 系统设计的工具，用于监控指定进程的状态。如果检测到指定进程启动，工具将标记为 "进程存在"；如果检测到进程退出，工具将自动执行暂停操作。此工具适用于需要确保某些进程长时间运行并自动处理进程退出的场景。

## 功能特性

- **监控指定进程**：检测系统中是否存在指定名称的进程。
- **自动暂停**：在指定进程退出时，自动执行暂停操作，防止后续操作继续进行。
- **仅支持 Windows 系统**：此工具仅在 Windows 操作系统上运行，适用于常见的桌面环境。

## 使用说明

### 环境要求

- 操作系统：Windows 10 或更高版本
- Go 语言环境：Go 1.18 及以上版本

### 安装步骤

1. **克隆项目**：
    ```bash
    git clone https://github.com/yourusername/xx-accelerator.git
    cd xx-accelerator
    ```

2. **编译项目**：
    ```bash
    go build -o xx-accelerator.exe
    ```

3. **运行工具**：
    在命令行中运行 `xx-accelerator.exe`，指定要监控的进程名称和检测间隔：
    ```bash
    ./xxx.exe
    ```



## 注意事项

- 本工具仅支持 Windows 系统，无法在其他操作系统上运行。
- 工具会持续检测指定进程的状态，直到手动停止运行。

## License

本项目采用 [MIT License](LICENSE)，欢迎贡献和改进。

