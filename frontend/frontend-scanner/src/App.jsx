import { useState } from 'react';

function App() {
  // 1. Lưu URL người dùng gõ
  const [url, setUrl] = useState('');

  // 2. Lưu trạng thái đang quét (để hiển thị chữ "Đang quét...")
  const [loading, setLoading] = useState(false);

  // 3. Lưu dữ liệu kết quả JSON từ Backend trả về
  const [result, setResult] = useState(null);

  // 4. Lưu thông báo lỗi nếu không gọi được API
  const [error, setError] = useState(null);

  // Hàm xử lý gửi Yêu cầu sang FastAPI
  const handleScan = async (e) => {
    e.preventDefault(); // Ngăn trang web bị reload lại
    if (!url) return alert('Vui lòng nhập URL!');

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
      });

      if (!response.ok) {
        throw new Error(`Lỗi kết nối: ${response.status}`);
      }

      const data = await response.json();
      setResult(data); // Lưu kết quả trả về
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'sans-serif', maxWidth: '800px', margin: '0 auto' }}>
      <h2>Test Scan Service (FastAPI + React)</h2>

      {/* Form nhập URL */}
      <form onSubmit={handleScan} style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
        <input
          type="text"
          placeholder="Nhập URL (ví dụ: https://example.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ flex: 1, padding: '10px', fontSize: '16px' }}
        />
        <button type="submit" disabled={loading} style={{ padding: '10px 20px', fontSize: '16px', cursor: 'pointer' }}>
          {loading ? 'Đang quét...' : 'Bắt đầu Quét'}
        </button>
      </form>

      {/* Hiển thị báo lỗi nếu có */}
      {error && (
        <div style={{ color: 'red', padding: '10px', border: '1px solid red', borderRadius: '4px' }}>
          ❌ **Lỗi:** {error}
        </div>
      )}

      {/* Hiển thị kết quả dạng JSON thô để test dữ liệu */}
      {result && (
        <div>
          <h3>
            Xếp hạng: <span style={{ color: 'red', fontSize: '24px', fontWeight: 'bold' }}>{result.grading}</span>
            {' '} | Điểm số: <span style={{ color: 'blue' }}>{result.scores?.final}/100</span>
          </h3>
          <h4>Dữ liệu thô từ Backend trả về (JSON):</h4>
          <pre style={{ background: '#f4f4f4', padding: '15px', borderRadius: '5px', overflowX: 'auto' }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default App;