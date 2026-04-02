# SGX-Step Kernel Module Fix Iterations (Kernel 6.12)

## 环境
- Kernel: 6.12.74+deb12-amd64 (Debian, PREEMPT_DYNAMIC)
- GCC: 12.2.0

---

## Iter 1 — 修复 CET/IBT Missing ENDBR 导致加载崩溃

### 问题
内核 6.12 默认启用 **CET IBT**（Control-flow Enforcement Technology, Indirect Branch Tracking）。
所有通过函数指针被间接调用的函数，必须在入口有 `ENDBR64` 指令。

直接定义 `init_module` / `cleanup_module` 时，编译器不能确保加上 `ENDBR64`，
内核在通过 `.init` 指针间接调用时触发 IBT 违例：

```
[  295.132625] Missing ENDBR: init_module+0x0/0x80 [sgx_step]
[  295.132671] RIP: 0010:init_module+0x0/0x80 [sgx_step]
```

### 修复
用命名函数 + `module_init()` / `module_exit()` 宏替代直接定义 `init_module` / `cleanup_module`。
宏会给函数加上正确的属性，使编译器和链接器生成 IBT 兼容的入口。

### 状态
- [x] 已修复，编译无错误，加载正常

```
[629.022129] [sgx-step] listening on /dev/sgx-step
```

无 `Missing ENDBR` 告警，模块加载不再挂起/崩溃。
