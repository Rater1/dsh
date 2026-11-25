# Windows standard-user isolation fixture

This fixture checks whether an Agent running as a separate Windows standard user can read a public marker while private fixture operations are denied. The reference run used two Windows accounts. The public marker was readable and all 12 private probes were denied under `dsh-run`. All probes used disposable synthetic fixtures.

## Run the check

1. Have a separate local Windows standard user named `dsh-run`. Use an account other than `dsh-run` to own the fixtures. Keep both package files together in an owner-controlled location.
2. In PowerShell 7 under the owner account, run the setup. It verifies the Microsoft signature of the built-in 64-bit Windows .NET Framework C# compiler, builds `Check-DshRunFixture.cs`, runs an owner check, and prints the checker path.

   ```powershell
   ./New-DshRunFixture.ps1 -AgentAccount dsh-run
   ```

3. Start a separate PowerShell window as `dsh-run`.

   ```powershell
   runas.exe /user:dsh-run powershell.exe
   ```

4. In that window, run the checker at the path printed by setup. For the independent account, require `"role":"agent"`, `"status":"PASS"`, and exit code `0`. The public marker must return `0`. Each of the 12 private access checks must return Windows error `5` (access denied).

   ```powershell
   & '<checker path printed by setup>'
   $LASTEXITCODE
   ```

## Scope

Use disposable fixtures only. For an actual deployment, keep service executables, configuration, logs, and credentials under a separate owner account, outside every directory the Agent can write. The isolation result applies to the two distinct user identities and the fixture permissions. Caddy, network access, and credential migration are outside this check.

When finished, the owner can remove the synthetic fixture directory printed by setup.

## 中文简述

这份指南演示如何用 `dsh-run` 标准账号启动独立 PowerShell，并通过一组假文件验证 Windows 访问权限。请分别检查持有者和 `dsh-run` 的结果。目录模板只用于合成测试，实际项目和服务目录的权限需要单独验收。
