// This function runs once the entire HTML page has been loaded.
document.addEventListener('DOMContentLoaded', () => {

    // Get references to all the HTML elements we'll need to interact with.
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const checkButton = document.getElementById('check-button');
    const buttonText = document.getElementById('button-text');
    const loader = document.getElementById('loader');
    
    const resultContainer = document.getElementById('result-container');
    const resultCard = document.getElementById('result-card');
    const resultTitle = document.getElementById('result-title');
    const resultConfidence = document.getElementById('result-confidence');
    const resultExplanation = document.getElementById('result-explanation');

    const errorContainer = document.getElementById('error-container');
    const errorMessage = document.getElementById('error-message');

    // Listen for the form to be submitted (e.g., when the user clicks the button).
    urlForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const url = urlInput.value.trim();
        if (!url) {
            showError('It looks like you forgot to enter a URL!');
            return;
        }

        setLoadingState(true);
        hideError();
        resultContainer.classList.add('hidden');

        try {
            const response = await fetch('/predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'The server had a problem. Please try again.');
            }

            const data = await response.json();
            displayResult(data);

        } catch (error) {
            console.error('Fetch Error:', error);
            showError(error.message);
        } finally {
            setLoadingState(false);
        }
    });

    /**
     * Manages the UI during the loading process.
     */
    function setLoadingState(isLoading) {
        if (isLoading) {
            buttonText.textContent = 'Analyzing...';
            loader.classList.remove('hidden');
            checkButton.disabled = true;
            urlInput.disabled = true;
        } else {
            buttonText.textContent = 'Analyze';
            loader.classList.add('hidden');
            checkButton.disabled = false;
            urlInput.disabled = false;
        }
    }

    /**
     * Displays the prediction result on the page with more personality.
     */
    function displayResult(data) {
        resultContainer.classList.remove('hidden', 'fade-in');
        // A trick to re-trigger the animation
        void resultContainer.offsetWidth; 
        resultContainer.classList.add('fade-in');

        resultConfidence.textContent = `Our AI is ${data.confidence} confident in this result.`;

        if (data.prediction === 'Phishing') {
            resultTitle.textContent = '⚠️ Be Careful! This looks suspicious.';
            resultCard.className = 'p-6 rounded-lg bg-red-900/50 border border-red-700';
            resultTitle.className = 'text-2xl font-semibold text-red-300';
            resultExplanation.textContent = "This URL has characteristics commonly found in phishing websites. It's best not to proceed or enter any personal information.";
        } else {
            resultTitle.textContent = "✅ All Clear! This URL looks safe.";
            resultCard.className = 'p-6 rounded-lg bg-green-900/50 border border-green-700';
            resultTitle.className = 'text-2xl font-semibold text-green-300';
            resultExplanation.textContent = "Our analysis didn't find any common signs of phishing. This link appears to be legitimate.";
        }
    }

    /**
     * Shows an error message to the user.
     */
    function showError(message) {
        errorMessage.textContent = message;
        errorContainer.classList.remove('hidden');
    }

    /**
     * Hides the error message container.
     */
    function hideError() {
        errorContainer.classList.add('hidden');
    }
});
