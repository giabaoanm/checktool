using SecAudit.Core.Models;

namespace SecAudit.Core.Services;

public static class FindingTriageInterpreter
{
    public static FindingTriage Interpret(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var scenario = DetectScenario(finding);
        var confidence = ClassifyConfidence(finding, scenario);
        var actionGroup = ClassifyActionGroup(finding.Severity, confidence);
        var explanation = BuildExplanation(scenario, finding.Severity, confidence);
        var steps = BuildSteps(scenario, actionGroup, finding);

        return new FindingTriage(actionGroup, confidence, scenario, explanation, steps);
    }

    private static string DetectScenario(Finding finding)
    {
        var text = CombinedText(finding);

        if (finding.Id.StartsWith("MAL", StringComparison.OrdinalIgnoreCase)
            || ContainsAny(text, "malware", "yara", "amcache", "prefetch", "hash feed", "script", ".lnk"))
        {
            return "Mã độc / file nghi vấn";
        }

        if (finding.Id.StartsWith("WEB-", StringComparison.OrdinalIgnoreCase)
            || ContainsAny(text, "web-incident", "deface", "website", "dns record", "tls certificate", "http header"))
        {
            return "Sự cố website/domain";
        }

        if (ContainsAny(text, "server-attack", "brute-force", "webshell", "credential-access",
                "lsass", "log cleared", "rdp", "ssh", "iis")
            || ContainsAny(text, "sqlmap", "exploit"))
        {
            return "Tấn công trực tuyến";
        }

        if (finding.Id.StartsWith("RA-", StringComparison.OrdinalIgnoreCase)
            || ContainsAny(text, "remote-access", "anydesk", "teamviewer", "ultraviewer",
                "winlogon", "ifeo", "vnc", "vpn", "persistence"))
        {
            return "Truy cập từ xa / duy trì";
        }

        if (ContainsAny(text, "cve", "patch", "kb", "windows update", "vulnerability", "lỗ hổng"))
        {
            return "Lỗ hổng / bản vá";
        }

        if (ContainsAny(text, "hardening", "firewall", "bitlocker", "secure boot",
                "credential guard", "uac", "smb", "powershell logging", "defender"))
        {
            return "Cấu hình bảo mật";
        }

        if (ContainsAny(text, "net-prof", "wifi", "wi-fi", "usb", "usbstor", "phone",
                "portable device", "ip policy", "network profile"))
        {
            return "Thiết bị / mạng theo chính sách";
        }

        if (ContainsAny(text, "lan", "open port", "share", "subnet", "network scan"))
        {
            return "Mạng nội bộ";
        }

        if (ContainsAny(text, "license", "kms", "kmspico", "activation", "genuine"))
        {
            return "Bản quyền / kích hoạt";
        }

        if (finding.Severity == Severity.Info
            || ContainsAny(text, "system-info", "inventory", "baseline"))
        {
            return "Thông tin hệ thống";
        }

        return "Rà soát chung";
    }

    private static string ClassifyConfidence(Finding finding, string scenario)
    {
        var text = CombinedText(finding);

        if (finding.Severity == Severity.Critical
            || ContainsAny(text, "webshell", "lsass", "credential-access", "success after failures",
                "hash feed malicious", "revoked signature", "ifeo", "winlogon")
            || ContainsAny(text, "ransom", "deface", "content changed", "tls invalid"))
        {
            return "Cao";
        }

        if (scenario is "Cấu hình bảo mật" or "Lỗ hổng / bản vá" or "Thiết bị / mạng theo chính sách"
            or "Bản quyền / kích hoạt")
        {
            return "Chính sách";
        }

        if (finding.Severity == Severity.Low || finding.Severity == Severity.Info)
        {
            return "Thấp";
        }

        if (ContainsAny(text, "amcache", "prefetch", "networklist", "history", "cache",
                "temp installer", "signed valid", "allowlist"))
        {
            return "Trung bình";
        }

        return finding.Severity >= Severity.High ? "Trung bình" : "Thấp";
    }

    private static string ClassifyActionGroup(Severity severity, string confidence)
    {
        if (severity == Severity.Critical)
        {
            return "Cần xử lý ngay";
        }

        if (severity == Severity.High)
        {
            return confidence == "Chính sách" ? "Cần xử lý" : "Cần xử lý ngay";
        }

        if (severity == Severity.Medium)
        {
            return "Cần xem lại";
        }

        return severity == Severity.Low ? "Có thể bỏ qua" : "Thông tin";
    }

    private static string BuildExplanation(string scenario, Severity severity, string confidence)
    {
        var prefix = confidence == "Chính sách"
            ? "Đây là phát hiện theo chính sách hoặc cấu hình, không phải bằng chứng trực tiếp về mã độc."
            : severity >= Severity.High
                ? "Đây là phát hiện cần ưu tiên vì có thể ảnh hưởng trực tiếp đến an toàn hệ thống."
                : "Đây là tín hiệu cần đối chiếu thêm trước khi kết luận.";

        return scenario switch
        {
            "Mã độc / file nghi vấn" =>
                prefix + " Ứng dụng thấy file, tiến trình hoặc dấu vết thực thi có đặc điểm bất thường; chỉ coi là mã độc chắc chắn khi có thêm xác nhận từ AV, hash feed tin cậy hoặc phân tích mẫu.",
            "Tấn công trực tuyến" =>
                prefix + " Dấu hiệu đến từ log hoặc trạng thái live, ví dụ dò mật khẩu, web scan, truy cập bất thường hoặc hành vi sau khai thác.",
            "Sự cố website/domain" =>
                prefix + " Dấu hiệu đến từ DNS/TLS/HTTP/nội dung website tại thời điểm thu thập, dùng để xác định deface, chuyển hướng lạ, lỗi dịch vụ hoặc thông báo mã hóa dữ liệu.",
            "Truy cập từ xa / duy trì" =>
                prefix + " Cần xác minh công cụ hoặc cơ chế duy trì truy cập này có được quản trị viên cho phép hay không.",
            "Lỗ hổng / bản vá" =>
                prefix + " Cần đối chiếu bản vá thực tế, phiên bản hệ điều hành và độ mới của cơ sở dữ liệu CVE trước khi kết luận.",
            "Cấu hình bảo mật" =>
                prefix + " Cấu hình này làm tăng rủi ro nếu máy bị tấn công, nhưng không tự chứng minh máy đã bị xâm nhập.",
            "Thiết bị / mạng theo chính sách" =>
                prefix + " Đây có thể là dấu vết Wi-Fi, USB, điện thoại, IP hoặc profile mạng; cần so với baseline của đơn vị.",
            "Mạng nội bộ" =>
                prefix + " Phát hiện này giúp rà soát bề mặt mạng nội bộ như cổng mở, chia sẻ hoặc host lạ.",
            "Bản quyền / kích hoạt" =>
                prefix + " Công cụ kích hoạt trái phép có thể đi kèm mã độc hoặc làm giảm độ tin cậy của hệ điều hành.",
            "Thông tin hệ thống" =>
                "Đây là thông tin nền để lập hồ sơ thiết bị, thường không cần xử lý riêng.",
            _ =>
                prefix + " Hãy đọc bằng chứng, đường dẫn, tài khoản và thời điểm trước khi thao tác."
        };
    }

    private static List<string> BuildSteps(string scenario, string actionGroup, Finding finding)
    {
        var steps = new List<string>();

        if (actionGroup == "Cần xử lý ngay")
        {
            steps.Add("Giữ nguyên bằng chứng trước khi xóa file, kill process hoặc gỡ dịch vụ.");
        }

        switch (scenario)
        {
            case "Mã độc / file nghi vấn":
                steps.Add("Ghi lại đường dẫn, SHA256, chữ ký số và user liên quan trong Evidence.");
                steps.Add("Quét lại bằng antivirus nội bộ hoặc Kaspersky ở chế độ custom scan.");
                steps.Add("Nếu AV/hash feed xác nhận độc hại, cô lập máy hoặc thiết bị lưu trữ rồi mới quarantine/xóa.");
                break;

            case "Tấn công trực tuyến":
                steps.Add("Xác định IP nguồn, tài khoản đích, dịch vụ bị nhắm tới và mốc thời gian.");
                steps.Add("Nếu còn đang diễn ra, chặn IP nguồn trên firewall hoặc tạm ngắt máy khỏi mạng ngoài.");
                steps.Add("Kiểm tra đăng nhập thành công, tiến trình lạ, service mới và thay đổi tài khoản sau thời điểm cảnh báo.");
                break;

            case "Sự cố website/domain":
                steps.Add("Bảo toàn thư mục evidence và manifest SHA256 trước khi sửa website hoặc đổi cấu hình DNS/CDN.");
                steps.Add("Nếu site đang deface, lỗi dịch vụ hoặc hiển thị thông báo mã hóa, chuyển traffic sang maintenance/CDN/WAF hoặc hạ tầng dự phòng.");
                steps.Add("Thu thêm log server-side: access/error log, application log, CMS/plugin audit log, database log, firewall/CDN/WAF log trong cùng khung giờ.");
                steps.Add("So sánh nội dung với bản triển khai sạch, rà webshell/backdoor/tài khoản quản trị lạ, khôi phục từ backup sạch và xoay vòng toàn bộ mật khẩu/API key liên quan.");
                break;

            case "Truy cập từ xa / duy trì":
                steps.Add("Hỏi quản trị viên xem công cụ hoặc cấu hình truy cập từ xa có được phê duyệt không.");
                steps.Add("Nếu không được phê duyệt, ngắt mạng, vô hiệu hóa service/task/autorun liên quan và đổi mật khẩu tài khoản bị ảnh hưởng.");
                steps.Add("Kiểm tra log đăng nhập và danh sách tài khoản quản trị viên cục bộ.");
                break;

            case "Lỗ hổng / bản vá":
                steps.Add("Kiểm tra Windows Update, số KB đã cài và ngày cập nhật gần nhất.");
                steps.Add("Cập nhật cơ sở dữ liệu CVE/rule nội bộ rồi quét lại nếu máy có thể truy cập nguồn cập nhật tin cậy.");
                steps.Add("Ưu tiên vá lỗi Critical/High trên máy chủ, máy có Internet hoặc máy chứa dữ liệu quan trọng.");
                break;

            case "Cấu hình bảo mật":
                steps.Add("So cấu hình hiện tại với baseline của đơn vị hoặc CIS/Microsoft Security Baseline.");
                steps.Add("Áp dụng nút khắc phục tự động nếu có; nếu không, thực hiện thủ công theo Remediation.");
                steps.Add("Khởi động lại và quét lại khi cấu hình yêu cầu reboot hoặc policy refresh.");
                break;

            case "Thiết bị / mạng theo chính sách":
                steps.Add("Đối chiếu với người dùng và baseline thiết bị/mạng được phép của đơn vị.");
                steps.Add("Nếu profile Wi-Fi, USB hoặc thiết bị không hợp lệ, lập biên bản trước khi xóa profile hoặc khóa thiết bị.");
                steps.Add("Với máy nội bộ không được Internet, kiểm tra kết nối ngoài chính sách và proxy/VPN.");
                break;

            case "Mạng nội bộ":
                steps.Add("Xác minh host/cổng/chia sẻ có thuộc hệ thống quản trị hợp lệ không.");
                steps.Add("Đóng dịch vụ không cần thiết hoặc giới hạn firewall theo phân vùng mạng.");
                steps.Add("Quét lại sau khi thay đổi để xác nhận bề mặt tấn công đã giảm.");
                break;

            case "Bản quyền / kích hoạt":
                steps.Add("Kiểm tra nguồn cài đặt Windows/Office và giấy phép hợp lệ.");
                steps.Add("Gỡ công cụ kích hoạt trái phép nếu có, sau đó quét malware toàn bộ máy.");
                steps.Add("Cân nhắc cài lại từ nguồn sạch nếu phát hiện công cụ crack đã chạy với quyền cao.");
                break;

            default:
                steps.Add("Đọc Evidence để xác định đường dẫn, tài khoản, IP, thời điểm và nguồn dữ liệu.");
                steps.Add("So sánh với baseline máy sạch hoặc thông tin người quản trị trước khi kết luận.");
                break;
        }

        if (!string.IsNullOrWhiteSpace(finding.Remediation)
            && !ContainsAny(finding.Remediation, "tham khảo tài liệu", "refer"))
        {
            steps.Add("Thực hiện khuyến nghị của phát hiện: " + finding.Remediation);
        }

        return steps;
    }

    private static string CombinedText(Finding finding)
        => string.Join(
            ' ',
            finding.Id,
            finding.Title,
            finding.Category,
            finding.Asset,
            finding.Evidence,
            finding.Remediation);

    private static bool ContainsAny(string value, string first, string second)
        => value.Contains(first, StringComparison.OrdinalIgnoreCase)
           || value.Contains(second, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(string value, string first, string second, string third)
        => ContainsAny(value, first, second)
           || value.Contains(third, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(string value, string first, string second, string third, string fourth)
        => ContainsAny(value, first, second, third)
           || value.Contains(fourth, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(
        string value,
        string first,
        string second,
        string third,
        string fourth,
        string fifth)
        => ContainsAny(value, first, second, third, fourth)
           || value.Contains(fifth, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(
        string value,
        string first,
        string second,
        string third,
        string fourth,
        string fifth,
        string sixth)
        => ContainsAny(value, first, second, third, fourth, fifth)
           || value.Contains(sixth, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(
        string value,
        string first,
        string second,
        string third,
        string fourth,
        string fifth,
        string sixth,
        string seventh)
        => ContainsAny(value, first, second, third, fourth, fifth, sixth)
           || value.Contains(seventh, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(
        string value,
        string first,
        string second,
        string third,
        string fourth,
        string fifth,
        string sixth,
        string seventh,
        string eighth)
        => ContainsAny(value, first, second, third, fourth, fifth, sixth, seventh)
           || value.Contains(eighth, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(
        string value,
        string first,
        string second,
        string third,
        string fourth,
        string fifth,
        string sixth,
        string seventh,
        string eighth,
        string ninth)
        => ContainsAny(value, first, second, third, fourth, fifth, sixth, seventh, eighth)
           || value.Contains(ninth, StringComparison.OrdinalIgnoreCase);
}
