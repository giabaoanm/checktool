using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace SecAudit.Modules.LanScanner.Probes;

/// <summary>
/// Passive SMBv1 detection: we send an SMB1 Negotiate Protocol Request advertising only
/// the "NT LM 0.12" dialect. A server that still accepts SMB1 replies with an SMB1 header
/// (0xFF 'S' 'M' 'B') and NT_STATUS=0. Modern Windows (SMB1 disabled/removed) either
/// drops the connection or replies with SMB2+. No authentication is attempted.
/// </summary>
public sealed class SmbV1Probe
{
    private readonly ILogger<SmbV1Probe> _logger;

    public SmbV1Probe(ILogger<SmbV1Probe> logger) => _logger = logger;

    public async Task<bool?> SupportsSmb1Async(IPAddress host, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await client.ConnectAsync(host, 445, cts.Token).ConfigureAwait(false);
            using var stream = client.GetStream();

            var packet = BuildNegotiateRequest();
            await stream.WriteAsync(packet, cts.Token).ConfigureAwait(false);

            var header = new byte[4];
            if (!await ReadExactAsync(stream, header, cts.Token).ConfigureAwait(false))
            {
                return null;
            }
            int length = (header[1] << 16) | (header[2] << 8) | header[3];
            if (length is <= 0 or > 65535)
            {
                return null;
            }
            var body = new byte[length];
            if (!await ReadExactAsync(stream, body, cts.Token).ConfigureAwait(false))
            {
                return null;
            }

            // SMB1 response starts with 0xFF 'S' 'M' 'B'; SMB2+ starts with 0xFE 'S' 'M' 'B'.
            if (body.Length >= 4 &&
                body[0] == 0xFF && body[1] == (byte)'S' && body[2] == (byte)'M' && body[3] == (byte)'B')
            {
                return true;
            }
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "SMB1 probe failed on {Host}", host);
            return null;
        }
    }

    private static byte[] BuildNegotiateRequest()
    {
        // NT LM 0.12 dialect (14 bytes with 0x02 prefix + null terminator).
        byte[] dialect = new byte[] { 0x02, (byte)'N', (byte)'T', (byte)' ', (byte)'L', (byte)'M',
            (byte)' ', (byte)'0', (byte)'.', (byte)'1', (byte)'2', 0x00 };

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        // SMB1 header: 0xFF 'S' 'M' 'B'
        w.Write(new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' });
        w.Write((byte)0x72); // SMB_COM_NEGOTIATE
        w.Write(new byte[4]); // NT Status
        w.Write((byte)0x18); // Flags
        w.Write((ushort)0xC853); // Flags2
        w.Write(new byte[12]); // PID high + signature
        w.Write((ushort)0); // reserved
        w.Write((ushort)0); // TID
        w.Write((ushort)0xFEFF); // PID low
        w.Write((ushort)0); // UID
        w.Write((ushort)0); // MID
        w.Write((byte)0); // WordCount
        // ByteCount (ushort) + dialect list
        w.Write((ushort)dialect.Length);
        w.Write(dialect);
        byte[] smb = ms.ToArray();

        // NetBIOS Session Service header: type=0x00, length (3 bytes big-endian)
        byte[] result = new byte[4 + smb.Length];
        result[0] = 0x00;
        result[1] = (byte)((smb.Length >> 16) & 0xFF);
        result[2] = (byte)((smb.Length >> 8) & 0xFF);
        result[3] = (byte)(smb.Length & 0xFF);
        Buffer.BlockCopy(smb, 0, result, 4, smb.Length);
        return result;
    }

    private static async Task<bool> ReadExactAsync(NetworkStream s, byte[] buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(read, buf.Length - read), ct).ConfigureAwait(false);
            if (n <= 0)
            {
                return false;
            }
            read += n;
        }
        return true;
    }
}
