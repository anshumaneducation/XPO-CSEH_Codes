fetch('/check-ip')
  .then(response => response.json())
  .then(data => {
    const statusElement = document.getElementById('status');
    statusElement.textContent = data.message;
    if (data.success) {
      statusElement.style.color = 'green';
    } else {
      statusElement.style.color = 'red';
    }
  })
  .catch(error => {
    console.error('Error:', error);
    document.getElementById('status').textContent = 'Error checking IP.';
  });
