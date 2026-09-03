---
title: "Test"
date: 2026-09-03
draft: true
---

Normal metin.

{{< note type="warning" title="Dikkat" >}}
Bu bir uyarı kutusu.
{{< /note >}}

{{< note type="danger" >}}
Bu kırmızı bir kutu.
{{< /note >}}

{{< details summary="Detayları göster" >}}
Gizli içerik burada.
{{< /details >}}

Vurgulanmış kod:

```powershell {hl_lines=[2]}
Get-Process
Invoke-Expression $payload
Write-Host "done"
```