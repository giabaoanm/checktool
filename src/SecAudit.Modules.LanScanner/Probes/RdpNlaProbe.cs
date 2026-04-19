using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace SecAudit.Modules.LanScanner.Probes;

/// <summary>
/// Passive RDP NLA detection. Sends an X.224 Connection Request with an RDP Negotiation
/// Request advertising SSL+CredSSP. Interpretation of the server's response:
///   * rdpNegRsp with selectedProto &gt;= 0x02  → NLA supported (good)
///   * rdpNegRsp with selectedProto = 0x00     → plain RDP only, NLA OFF (finding)
///   * rdpNegFailure                           → server won't negotiate, can't determine
/// No auth is sent. The TCP connection is closed immediately after the first reply.
/// </summary>
public sealed class RdpNlaProbe
{
    private readonly ILogger<RdpNlaProbe> _logger;

    public RdpNlaProbe(ILogger<RdpNlaProbe> logger) => _logger = logger;

    public enum RdpNlaResult
    {
        Unknown,
        NlaEnabled,
        NlaDisabled
    }

    public async Task<RdpNlaResult> ProbeAsync(IPAddress host, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await client.ConnectAsync(host, 3389, cts.Token).ConfigureAwait(false);
            using var stream = client.GetStream();

            var req = BuildX224ConnectionRequest();
            await stream.WriteAsync(req, cts.Token).ConfigureAwait(false);

            var buf = new byte[64];
            int n = await stream.ReadAsync(buf, cts.Token).ConfigureAwait(false);
            if (n < 11)
            {
                return RdpNlaResult.Unknown;
            }
            // TPKT: buf[0]=0x03, buf[1]=0x00, buf[2..3]=length
            // X.224 header begins at buf[4]; rdpNegRsp/rdpNegFailure starts at buf[11] typically.
            int idx = 11;
            if (n <= idx)
            {
                return RdpNlaResult.Unknown;
            }
            byte type = buf[idx];
            if (type == 0x02) // TYPE_RDP_NEG_RSP
            {
                if (n < idx + 8)
                {
                    return RdpNlaResult.Unknown;
                }
                // selectedProtocol is at idx+4 little-endian uint32
                uint proto = BitConverter.ToUInt32(buf, idx + 4);
                // 0x00=PROTOCOL_RDP (NLA off), 0x01=SSL, 0x02=HYBRID(CredSSP), 0x08=RDSTLS, ...
                return (proto & 0x02) != 0 ? RdpNlaResult.NlaEnabled : RdpNlaResult.NlaDisabled;
            }
            if (type == 0x03) // TYPE_RDP_NEG_FAILURE
            {
                return RdpNlaResult.Unknown;
            }
            return RdpNlaResult.Unknown;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "RDP probe failed on {Host}", host);
            return RdpNlaResult.Unknown;
        }
    }

    private static byte[] BuildX224ConnectionRequest()
    {
        // rdpNegReq: type=0x01, flags=0x00, length=0x0008, requestedProtocols=0x00000003 (SSL|HYBRID)
        byte[] neg = new byte[] { 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 };
        // X.224 Connection Request (TPDU type 0xE0)
        // length(1) | type(0xE0) | dstRef(2) | srcRef(2) | class(1) | rdpNegReq(8) = 15 bytes
        byte[] x224 = new byte[7 + neg.Length];
        x224[0] = (byte)(x224.Length - 1); // length indicator (not including this byte)
        x224[1] = 0xE0; // CR CDT
        x224[2] = 0x00; x224[3] = 0x00; // dst ref
        x224[4] = 0x00; x224[5] = 0x00; // src ref
        x224[6] = 0x00; // class option
        Buffer.BlockCopy(neg, 0, x224, 7, neg.Length);

        // TPKT header: 0x03 0x00 length(2 big endian)
        int total = 4 + x224.Length;
        byte[] tpkt = new byte[total];
        tpkt[0] = 0x03; tpkt[1] = 0x00;
        tpkt[2] = (byte)((total >> 8) & 0xFF);
        tpkt[3] = (byte)(total & 0xFF);
        Buffer.BlockCopy(x224, 0, tpkt, 4, x224.Length);
        return tpkt;
    }
}
