<p align="center">
  <a href="CONTRIBUTING.md">Русский</a> · <a href="CONTRIBUTING.en.md">English</a> · <strong>简体中文</strong>
</p>

# 参与 Hydrat 开发

欢迎社区贡献。提交更改前请先阅读本指南。

---

## 技术栈与要求

- **Go：**1.26+
- **网络栈：**WireGuard、Xray-core、Tor、nftables
- **容器：**Docker 和 Docker Compose
- **操作系统：**Linux 5.10+，支持 nftables 和 WireGuard

---

## 开发流程

### 1. 准备环境

克隆仓库并下载依赖：

```bash
git clone https://github.com/only-hydrat/hydrat.git
cd hydrat
go mod download
```

### 2. 运行测试

修改代码前，请确认现有测试全部通过：

```bash
go test ./...
```

显示详细输出：

```bash
go test -v ./...
```

### 3. 格式化并检查代码

代码必须符合 Go 格式，并通过静态检查：

```bash
gofmt -s -w .
go vet ./...
```

### 4. 提交

项目采用 [Conventional Commits](https://www.conventionalcommits.org/)：

- `feat:` 新功能
- `fix:` 错误修复
- `refactor:` 不改变行为的代码重构
- `docs:` 文档更改
- `test:` 添加或修复测试
- `chore:` 日常维护和依赖更新

示例：

```text
feat(routing): add fallback latency threshold for active outbounds
```

---

## 提交拉取请求

1. 为任务创建独立分支：
   ```bash
   git checkout -b feat/my-feature
   ```
2. 实现更改，并为新行为添加测试。
3. 确认 `go test ./...` 和 `go vet ./...` 成功完成。
4. 创建合并到 `main` 的 Pull Request，并完整填写模板。
5. 等待自动检查和代码审查。
