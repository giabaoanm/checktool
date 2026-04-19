Get-EventLog -LogName Application -Newest 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'SecAudit' -or $_.Source -eq '.NET Runtime' -or $_.Source -eq 'Application Error' } |
    Select-Object -First 5 TimeGenerated, Source, EntryType, @{Name='Msg'; Expression={ $_.Message.Substring(0, [Math]::Min(800, $_.Message.Length)) }} |
    Format-List
