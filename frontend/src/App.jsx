import { useState } from 'react';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showJson, setShowJson] = useState(false);

  const [loadingRemediation, setLoadingRemediation] = useState(false);
  const [remediationData, setRemediationData] = useState(null);
  
  const [activeTab, setActiveTab] = useState('nginx');

  // State quản lý hiệu ứng Copy
  const [copiedJson, setCopiedJson] = useState(false);
  const [copiedSnippetId, setCopiedSnippetId] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return alert('Vui lòng nhập URL!');

    setLoading(true);
    setError(null);
    setResult(null);
    setRemediationData(null);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) throw new Error(`Lỗi kết nối: ${response.status}`);
      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateRemediation = () => {
    setLoadingRemediation(true);
    setRemediationData(null);

    setTimeout(() => {
      const backendRemediation = result?.remediation?.remediation || result?.remediation || [];
      
      const nginxData = [];
      const apacheData = [];

      backendRemediation.forEach((item) => {
        if (item.recommendation?.nginx) {
          nginxData.push({
            header: item.title,
            fix: item.recommendation.nginx,
            warnings: item.warnings || [],
            severity: item.severity
          });
        }
        if (item.recommendation?.apache) {
          apacheData.push({
            header: item.title,
            fix: item.recommendation.apache,
            warnings: item.warnings || [],
            severity: item.severity
          });
        }
      });

      setRemediationData({
        nginx: nginxData,
        apache: apacheData
      });
      
      setLoadingRemediation(false);
    }, 600);
  };

  // Hàm xử lý Copy vào Clipboard kèm timeout reset trạng thái
  const handleCopy = (text, type, id = null) => {
    navigator.clipboard.writeText(text);
    if (type === 'json') {
      setCopiedJson(true);
      setTimeout(() => setCopiedJson(false), 2000);
    } else if (type === 'snippet') {
      setCopiedSnippetId(id);
      setTimeout(() => setCopiedSnippetId(null), 2000);
    }
  };

  const getGradeColor = (grade) => {
    switch (grade) {
      case 'A+': case 'A': return 'bg-emerald-500 text-white';
      case 'B': return 'bg-blue-500 text-white';
      case 'C': return 'bg-amber-500 text-white';
      case 'D': case 'E': return 'bg-orange-500 text-white';
      default: return 'bg-rose-600 text-white';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans">
      <div className="max-w-5xl mx-auto space-y-8">
        
        <header className="text-center space-y-2">
          <h1 className="text-3xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
            Web Security Assessor
          </h1>
          <p className="text-slate-400 text-sm">Hệ thống đánh giá cấu hình bảo mật website tự động</p>
        </header>

        <form onSubmit={handleScan} className="flex gap-3 bg-slate-900 p-3 rounded-2xl border border-slate-800 shadow-xl">
          <input
            type="text"
            placeholder="Nhập mục tiêu (vd: https://example.com hoặc http://localhost:8080)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 bg-slate-950 px-4 py-3 rounded-xl border border-slate-800 focus:outline-none focus:border-cyan-500 text-slate-200 placeholder-slate-500 text-sm"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-cyan-600 hover:bg-cyan-500 text-white px-6 py-3 rounded-xl font-semibold text-sm transition-all shadow-lg shadow-cyan-900/30 disabled:opacity-50 cursor-pointer"
          >
            {loading ? 'Đang quét sâu...' : 'Bắt đầu Quét'}
          </button>
        </form>

        {error && (
          <div className="bg-rose-950/50 border border-rose-800 text-rose-300 p-4 rounded-xl text-sm">
            ❌ <strong>Lỗi hệ thống:</strong> {error}
          </div>
        )}

        {result && (
          <div className="space-y-6 animate-fadeIn">
            
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
              <div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">Mục tiêu kiểm tra</span>
                <h2 className="text-lg font-bold text-slate-100 mt-0.5 break-all font-mono">{result.meta?.target_url}</h2>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800 text-xs text-slate-300">
                  Mã phản hồi: <strong className="text-emerald-400">{result.meta?.status_code}</strong>
                </span>
                <span className="bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800 text-xs text-slate-300">
                  Bảo mật HTTPS: <strong className={result.meta?.is_https ? "text-emerald-400" : "text-rose-400"}>{result.meta?.is_https ? "Có" : "Không"}</strong>
                </span>
                <span className="bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800 text-xs text-slate-300">
                  Cookies phát hiện: <strong className="text-cyan-400">{result.meta?.cookie_count}</strong>
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-center justify-between">
                <div>
                  <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Xếp hạng bảo mật</p>
                  <p className="text-3xl font-black mt-1 text-slate-100">Hạng {result.grading}</p>
                </div>
                <div className={`w-16 h-16 rounded-2xl flex items-center justify-center text-3xl font-black shadow-lg ${getGradeColor(result.grading)}`}>
                  {result.grading}
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between">
                <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Điểm tổng kết</p>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-4xl font-black text-cyan-400">{result.scores?.final}</span>
                  <span className="text-slate-500 text-sm">/ 100 điểm</span>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between">
                <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Điểm thành phần</p>
                <div className="grid grid-cols-3 gap-2 text-center mt-2">
                  <div className="bg-slate-950 p-2 rounded-xl border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">Headers</span>
                    <span className="font-bold text-sm text-amber-400">{result.scores?.headers}</span>
                  </div>
                  <div className="bg-slate-950 p-2 rounded-xl border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">Cookies</span>
                    <span className="font-bold text-sm text-rose-400">{result.scores?.cookies}</span>
                  </div>
                  <div className="bg-slate-950 p-2 rounded-xl border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">TLS/SSL</span>
                    <span className="font-bold text-sm text-emerald-400">{result.scores?.tls}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>🛡️ Bảo mật HTTP Headers</span>
                  <span className="text-xs text-slate-500 font-normal">Trạng thái</span>
                </h3>
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {result.details?.headers && Object.entries(result.details.headers).map(([key, val]) => (
                    <div key={key} className="bg-slate-950 p-3 rounded-xl border border-slate-800/80 flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">{key}</span>
                      <span className={`px-2 py-0.5 rounded font-semibold uppercase text-[10px] ${
                        val.status === 'pass' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                        val.status === 'warn' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                        'bg-rose-950 text-rose-400 border border-rose-800'
                      }`}>
                        {val.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-6">
                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
                  <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">🍪 Đánh giá Cookie (Worst Cookie)</h3>
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-xs space-y-1">
                    <p className="text-slate-400">Tên cookie: <span className="text-cyan-400 font-mono font-bold">{result.details?.cookie_scoring?.worst_cookie?.name || 'Không có / Không phát hiện'}</span></p>
                    <p className="text-slate-400">Nguyên nhân: <span className="text-rose-400">{result.details?.cookie_scoring?.worst_cookie?.reason || 'Được cấu hình an toàn'}</span></p>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
                  <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">🔒 Trạng thái mã hóa TLS/SSL</h3>
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-xs space-y-1">
                    <p className="text-slate-400">Phiên bản TLS: <span className="text-emerald-400 font-mono">{result.details?.tls?.tls_version?.value || 'N/A'}</span></p>
                    <p className="text-slate-400">Chứng chỉ số: <span className="text-emerald-400">{result.details?.tls?.certificate_trust?.reason || 'N/A'}</span></p>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950 border border-cyan-900/50 rounded-2xl p-6 flex flex-col md:flex-row items-center justify-between gap-4 shadow-xl">
              <div>
                <h3 className="text-base font-bold text-cyan-400">💡 Đề xuất cấu hình khắc phục (Remediation Guide)</h3>
                <p className="text-xs text-slate-400 mt-1">Tạo tự động đoạn mã Hardening dựa trên dữ liệu quét trả về từ server.</p>
              </div>
              <button
                onClick={handleGenerateRemediation}
                disabled={loadingRemediation}
                className="bg-cyan-600 hover:bg-cyan-500 text-white px-5 py-2.5 rounded-xl text-xs font-semibold transition-all shadow-lg shadow-cyan-900/40 disabled:opacity-50 cursor-pointer whitespace-nowrap"
              >
                {loadingRemediation ? '⏳ Đang tổng hợp giải pháp...' : '⚡ Sinh cấu hình khắc phục'}
              </button>
            </div>

            {remediationData && (
              <div className="bg-slate-900 border border-cyan-800/60 rounded-2xl p-6 space-y-4 animate-fadeIn">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-slate-800 pb-3 gap-3">
                  <h4 className="text-sm font-bold text-cyan-300">🛠️ Chọn nền tảng Web Server mục tiêu</h4>
                  
                  <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800">
                    <button
                      onClick={() => setActiveTab('nginx')}
                      className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                        activeTab === 'nginx' ? 'bg-cyan-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Nginx Server
                    </button>
                    <button
                      onClick={() => setActiveTab('apache')}
                      className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                        activeTab === 'apache' ? 'bg-cyan-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Apache HTTP Server
                    </button>
                  </div>
                </div>

                <div className="space-y-4 pt-2">
                  {(activeTab === 'nginx' ? remediationData.nginx : remediationData.apache).map((item, idx) => {
                    const snippetId = `${activeTab}-${idx}`;
                    const isCopied = copiedSnippetId === snippetId;

                    return (
                      <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                        <div className="flex justify-between items-center">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-bold text-amber-400">{item.header}</span>
                            {item.severity === 'critical' || item.severity === 'high' ? (
                              <span className="bg-rose-900/50 text-rose-400 px-2 py-0.5 rounded text-[10px] uppercase font-bold border border-rose-800">
                                Mức độ: {item.severity}
                              </span>
                            ) : null}
                          </div>
                          <span className="text-[10px] text-slate-500 uppercase font-mono bg-slate-900 px-2 py-1 rounded">{activeTab} syntax</span>
                        </div>
                        
                        <div className="relative group mt-2">
                          <button
                            onClick={() => handleCopy(item.fix, 'snippet', snippetId)}
                            className={`absolute top-2 right-2 text-[10px] px-2 py-1.5 rounded border transition-all duration-200 cursor-pointer ${
                              isCopied 
                                ? 'bg-emerald-900/80 text-emerald-400 border-emerald-700 opacity-100' 
                                : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
                            }`}
                          >
                            {isCopied ? '✓ Đã sao chép' : '📋 Copy'}
                          </button>
                          
                          <pre className="text-xs font-mono text-emerald-300 overflow-x-auto bg-slate-900 p-4 rounded-lg border border-slate-800">
                            {item.fix}
                          </pre>
                        </div>
                        
                        {item.warnings && item.warnings.length > 0 && (
                          <div className="bg-rose-950/30 border border-rose-900/50 p-3 rounded-lg space-y-1 mt-2">
                            <p className="text-[11px] font-bold text-rose-400 flex items-center gap-1">⚠️ Cảnh báo thay đổi:</p>
                            <ul className="list-disc list-inside text-[11px] text-rose-300/80 space-y-0.5">
                              {item.warnings.map((w, i) => (
                                <li key={i}>{w}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    );
                  })}

                  {(activeTab === 'nginx' ? remediationData.nginx : remediationData.apache).length === 0 && (
                    <div className="text-center text-slate-500 text-sm py-8 bg-slate-950 rounded-xl border border-slate-800 border-dashed">
                      Không phát hiện cấu hình nào cần thiết phải bổ sung cho {activeTab.toUpperCase()}.
                    </div>
                  )}
                </div>
              </div>
            )}

            <div className="flex justify-between items-center pt-2">
              <p className="text-xs text-slate-500">Mã định danh quét hoàn tất thành công.</p>
              <button
                onClick={() => setShowJson(!showJson)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-xl text-xs font-semibold transition-all border border-slate-700 cursor-pointer"
              >
                {showJson ? 'Ẩn báo cáo JSON thô' : 'Xem toàn bộ JSON Response'}
              </button>
            </div>

            {showJson && (
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 animate-fadeIn">
                <div className="flex justify-between items-center mb-3">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Dữ liệu thô từ Backend trả về (JSON)</h3>
                  <button 
                    onClick={() => handleCopy(JSON.stringify(result, null, 2), 'json')}
                    className={`text-[10px] px-3 py-1.5 rounded border transition-all duration-200 cursor-pointer ${
                      copiedJson 
                        ? 'bg-emerald-900/80 text-emerald-400 border-emerald-700' 
                        : 'bg-slate-800 hover:bg-slate-700 text-cyan-400 border-slate-700'
                    }`}
                  >
                    {copiedJson ? '✓ Đã sao chép' : '📋 Copy JSON'}
                  </button>
                </div>
                <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs text-cyan-300 overflow-x-auto max-h-96">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            )}

          </div>
        )}

      </div>
    </div>
  );
}

export default App;