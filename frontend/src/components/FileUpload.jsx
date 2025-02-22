import { useState } from "react";
import axios from "axios";
import "../index.css";

function FileUpload() {
  const [file, setFile] = useState(null);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleUpload = async () => {
    if (!file) {
      setError("Please select a file first");
      return;
    }

    setIsLoading(true);
    setError("");
    
    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await axios.post(
        "http://localhost:5001/upload",
        formData
      );

      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.error || "Scan failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const getVerdictStyle = () => {
    if (!results) return {};
    switch(results.verdict) {
      case "Malicious": return { color: "red", fontWeight: "bold" };
      case "Suspicious": return { color: "orange", fontWeight: "bold" };
      case "Clean": return { color: "green", fontWeight: "bold" };
      default: return {};
    }
  };

  return (
    <div className="scanner-container">
      <h1>🛡️ Malware Scanner</h1>
      
      <div className="upload-box">
        <input
          type="file"
          onChange={(e) => {
            setFile(e.target.files[0]);
            setResults(null); // Reset previous results
          }}
          accept=".exe,.pdf,.docx"
        />
        <button onClick={handleUpload} disabled={isLoading}>
          {isLoading ? "🔍 Scanning..." : "🚀 Scan Now"}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {results && (
        <div className="results-card">
          <h2>Scan Results</h2>
          
          <div className="verdict" style={getVerdictStyle()}>
            {results.verdict}
          </div>

          <div className="file-info">
            <span>File Type:</span>
            <span>{results.file_type}</span>
          </div>

          {results.findings.length > 0 && (
            <div className="findings">
              <h3> Detected Issues:</h3>
              <ul>
                {results.findings.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default FileUpload;