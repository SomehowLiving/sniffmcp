#!/usr/bin/env bash
# Windows toast notification from WSL (no-op elsewhere). Usage: notify-windows.sh "Title" "Message"
PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
[ -x "$PS" ] || exit 0
title=${1//\'/\'\'}; msg=${2//\'/\'\'}
"$PS" -NoProfile -NonInteractive -Command "
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
\$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
\$x = \$t.GetElementsByTagName('text')
\$x.Item(0).AppendChild(\$t.CreateTextNode('$title')) | Out-Null
\$x.Item(1).AppendChild(\$t.CreateTextNode('$msg')) | Out-Null
\$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(\$app).Show([Windows.UI.Notifications.ToastNotification]::new(\$t))
" >/dev/null 2>&1 || true
