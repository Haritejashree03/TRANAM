// Emergency Alert Function
function sendEmergencyAlert() {
    if (confirm('Are you sure you want to send an emergency alert?')) {
        // Get current location
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                function(position) {
                    const location = `${position.coords.latitude}, ${position.coords.longitude}`;
                    
                    fetch('/api/emergency', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            location: location
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert('Emergency alert sent! Help is on the way.');
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('Error sending alert. Please try again.');
                    });
                },
                function(error) {
                    // If location access is denied, send without location
                    fetch('/api/emergency', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            location: 'Unknown'
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert('Emergency alert sent! Help is on the way.');
                    });
                }
            );
        }
    }
}

// Live Streaming Simulation
function startLiveStream() {
    alert('Live streaming feature will be implemented with camera integration');
    // This would integrate with WebRTC for actual live streaming
}

// Map Viewing
function viewMap() {
    alert('Map view will show your current location and nearby safe places');
    // This would integrate with Google Maps or similar service
}

// Form validation
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const requiredFields = form.querySelectorAll('[required]');
            let valid = true;
            
            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    valid = false;
                    field.classList.add('is-invalid');
                } else {
                    field.classList.remove('is-invalid');
                }
            });
            
            if (!valid) {
                e.preventDefault();
                alert('Please fill in all required fields.');
            }
        });
    });
});