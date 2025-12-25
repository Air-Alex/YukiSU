# 安装指导

您可以前往 [KernelSU 文档 - 安装](https://kernelsu.org/guide/installation.html) 获取有关如何安装的参考，这里只是额外的说明。

## 通过加载可加载内核模块 (LKM) 进行安装

请参阅 [KernelSU 文档 - LKM 安装](https://kernelsu.org/guide/installation.html#lkm-installation)

从 Android 12 开始，搭载内核版本 5.10 或更高版本的设备必须搭载 GKI 内核。因此你或许可以使用 LKM 模式。

## 通过安装内核进行安装

请参阅 [KernelSU 文档 - GKI 模式安装](https://kernelsu.org/guide/installation.html#gki-mode-installation)

虽然某些设备可以使用 LKM 模式安装，但无法使用 GKI 内核将其安装到设备上；因此，需要手动修改内核进行编译。例如：

- 欧珀（一加、真我）
- 魅族

具体可以参考SukiSU的文档进行操作，您能找到这个文档说明您也不简单，应该是懂点操作的（x
