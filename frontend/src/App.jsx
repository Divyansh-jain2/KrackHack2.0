import FileUpload from "./components/FileUpload";

function App() {
  return (
    <div className="app">
      <ErrorBoundary>
        <FileUpload />
      </ErrorBoundary>
    </div>
  );
}

export default App;