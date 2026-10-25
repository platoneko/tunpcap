# TunPcap host 脚本

`tunpcap.py` 通过 adb 控制手机上的 TunPcap：开始抓包、停止抓包、把 pcap 拉回本机。只依赖 Python 3 标准库和 PATH 里的 `adb`。

## 用法

```bash
# 开始：只让指定 App 走 TunPcap 的 VPN，全部流量从 GLOBAL 组选中的节点出去
python3 tools/tunpcap.py start --serial <SERIAL> --app com.android.chrome --name t1.pcap

# 停止：pcap 落盘后关闭 VPN
python3 tools/tunpcap.py stop --serial <SERIAL>

# 拉回：等文件大小稳定后 adb pull，并校验是 raw IP（linktype 101）pcap
python3 tools/tunpcap.py pull --serial <SERIAL> --name t1.pcap --out ./_local/tmp/
```

`--serial` 必填，脚本不会自动挑设备。`--app` 可写多个包名，用逗号分隔。

等价的裸 adb 指令（参数名与 PCAPdroid 的 CaptureCtrl 相同）：

```bash
adb -s <SERIAL> shell am start -n dev.plat1ko.tunpcap/.CaptureCtrl \
  --es action start --es pcap_dump_mode pcap_file \
  --es app_filter <包名[,包名]> --ez full_payload true --es pcap_name <文件名>
adb -s <SERIAL> shell am start -n dev.plat1ko.tunpcap/.CaptureCtrl --es action stop
```

pcap 存在手机 `/sdcard/Download/TunPcap/<文件名>`。同名文件（包括未完成的 `<文件名>.part`）已存在时拒绝开始，不会覆盖。

- **什么时候算开始**：App 先等配置加载完、确认 `GLOBAL` 选的是代理节点，才建 VPN，然后在 logcat 写 `started file=...`。脚本 `start` 以这一行（或 `rejected: ...`）为准，所以它报告开始时，被抓 App 的流量已经从节点出去了，不会有直连窗口。
- **什么时候算完成**：抓包期间写的是 `<文件名>.part`，`stop` 后数据全部落盘才改名为正式文件名。脚本 `pull` 等正式文件名出现才拉。进程被杀时会留下 `.part`，那是不完整的文件。
- **授权弹窗还开着时发 `stop`**：会取消这次开始，之后再点「确定」也不会启动。

## 使用前

1. 在 TunPcap 界面导入 Clash 配置，切到「全局」模式，在 `GLOBAL` 组里选好节点。`GLOBAL` 选的是 `DIRECT` / `REJECT` 时拒绝开始抓包。
2. 抓包期间的模式固定为全局，结束后自动恢复为原来的模式。

## 需要知道的行为

- **每次开始都可能弹 VPN 授权窗**：只要上次抓包后有别的 App（比如 FlClash）拿过 VPN，授权就会失效。脚本等 10 秒没看到 VPN 起来，会提示去手机上点授权，点完按回车。
- **抓完不会自动恢复 FlClash**：需要手动打开 FlClash 的 VPN。
- **fake-ip**：如果配置里 DNS 用的是 fake-ip，pcap 里的服务器地址是 `198.18.0.0/16` 段的假地址，这是预期行为。
- **只有 IPv4**：抓包模式下 VPN 不配 IPv6，安卓会阻断被抓 App 的 IPv6，App 回退到 IPv4。
- **诊断**：所有开始 / 停止 / 拒绝的结果都在 logcat 里，`adb logcat -d | grep TunPcap`。

## 测试

```bash
python3 -m unittest tools/test_tunpcap.py -v
```
