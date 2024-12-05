document.getElementById('scanButton').addEventListener('click', () => {
    const statusElement = document.getElementById('status');
    const resultElement = document.getElementById('result');
    const resultMessageElement = document.getElementById('resultMessage');
  
    statusElement.textContent = "Scanning...";
    resultElement.classList.add('hidden');
  
    // Send current URL to the backend
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const currentUrl = tabs[0].url;
  
      fetch('http://127.0.0.1:5000/check_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: currentUrl })
      })
        .then(response => response.json())
        .then(data => {
          resultElement.classList.remove('hidden');
          resultMessageElement.textContent = data.status === 'safe'
            ? 'The website is safe!'
            : 'Warning! This website might be phishing.';
        })
        .catch(error => {
          resultElement.classList.remove('hidden');
          resultMessageElement.textContent = 'Error: Unable to fetch results.';
          console.error(error);
        });
  
      statusElement.textContent = "Analysis Complete!";
    });
  });
  