# HIP 标识管理

## 用户操作

在 **Settings → HIP identity** 中查看和编辑主机名、机器 GUID、网卡 GUID、MAC。导入、生成只产生草稿；**Save HIP identity** 将四个字段保存到 `POLYGP_HIP_CONF` 指向的私有配置，**Discard HIP edits** 恢复服务器最近报告的值。

HIP 保存与账号设置的保存独立。前者写入持久卷，后者仍受 `.env` 和进程生命周期影响。页面切换、状态刷新和保存失败都会保留 HIP 草稿；关闭页面时有未保存提示。

## 文件格式

导出文件名为 `polygp-hip-identity.json`。以下仅为格式示例，不是默认身份：

```json
{
  "format": "polygp-hip-identity",
  "version": 1,
  "identity": {
    "HOST_NAME": "DESKTOP-DEMO123",
    "HOST_ID": "4f35f1ae-9708-4f15-bc9f-84bf11783918",
    "NIC_GUID": "{6E225D31-9146-484E-B89F-A0210966CC62}",
    "NIC_MAC": "02-8A-7B-4C-9D-12"
  }
}
```

- 导出当前表单中的四个值，包括未保存的编辑。不会导出密码、会话 Cookie 或其他 HIP 配置。
- 导入接受上述带版本号的 JSON，也接受仅包含四个字段的 JSON 对象。
- `.conf` 导入只提取四个字段的普通赋值语句；不会 source 文件，不执行命令，也不导入其他字段。重复字段、非法值、未知 JSON 字段和不支持的版本会被拒绝。
- 文件最大 64 KB。MAC 中的冒号会规范化为短横线，机器 GUID 使用小写，网卡 GUID 使用带大括号的大写格式。
- 全零 UUID 和历史共用示例 MAC 不能作为新配置保存。旧配置仍可查看和导出，但重新导入时需要先修正这些值。

要复制同一身份，可导出后在另一个实例导入；需要不同身份时，在各实例分别生成，不共享导出文件或 `polygp-hip` 数据卷。随机生成不能提供数学上的绝对不重复保证，但不会直接复制维护者的配置。

## 保存与生效

`hip/hip_identity.py` 校验所有字段后替换配置中的标识赋值，保留其余 HIP 内容。保存使用同目录临时文件与原子替换，权限为 `0600`。磁盘写入失败时旧配置保持不变。

界面保存请求携带读取时的文件版本。另一页面或外部程序已修改配置时，请求会被拒绝，避免覆盖未查看的更改。可以先导出草稿，再放弃编辑，查看最新内容后重新修改。

控制器在启动隧道时，将四个标识保存为该会话的固定值，并通过子进程环境传给 HIP 脚本。保存新配置不会改变当前会话的周期性 HIP 报告。固定值也保存在可恢复会话记录中，因此重启恢复继续使用原标识；下一次全新登录才读取新配置。**Identity used by the current session** 可展开查看当前会话的值。

旧版本的会话记录没有标识快照，升级后第一次恢复时会从现有私有配置建立快照。自定义 HIP 脚本若不读取 `POLYGP_SESSION_HOST_NAME`、`POLYGP_SESSION_HOST_ID`、`POLYGP_SESSION_NIC_GUID`、`POLYGP_SESSION_NIC_MAC`，就不会获得此固定行为。默认脚本已支持它们。

首次启动只在私有配置不存在时生成，不自动替换已有标识。生成失败时保留控制面板供修复；HIP 报告脚本要求存在私有配置，不使用共用示例回退。

## 接口

所有接口遵循控制面板的 `CONTROL_TOKEN` 认证。POST 使用 `application/x-www-form-urlencoded`，并要求 `X-PolyGP-HIP: 1`；不接受通过 GET 修改标识。

| 接口 | 用途 |
| --- | --- |
| `GET /hip` | 读取已保存字段、版本、格式问题和当前会话字段 |
| `POST /hip/generate` | 生成四个候选字段，不写入配置 |
| `POST /hip/validate` | 校验 `content` 中的导入文本，返回规范化字段 |
| `POST /hip/save` | 校验 `content`，检查 `revision` 并原子保存 |

导出在浏览器中完成，JSON 仅由这四个表单字段构造。HIP 标识也包含在已认证的 `/status` 响应中，用于更新页面；读取失败只在该设置组中提示，不影响其他状态显示。

## 验证

`python3 -m unittest discover -s tests` 覆盖导入与保存、非法输入、并发修改、失败保留、文件权限、HTTP 认证与方法限制，以及修改默认值后原会话和恢复会话的实际 HIP XML 输出。

`python3 scripts/preview_panel.py` 使用内存中的模拟标识。`/mock?state=connected&fail_action=hip` 可检查保存失败后的草稿保留，不影响真实 VPN 或私有配置。
