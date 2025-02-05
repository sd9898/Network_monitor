# NetGuard

## Description
NetGuard is a network monitoring and security analysis tool that checks the reputation of visited URLs using VirusTotal and Google Safe Browsing. It captures network traffic and provides a web dashboard to display the results.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/netguard.git
   cd netguard
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables for API keys:
   ```bash
   export VIRUSTOTAL_API_KEY='your_virustotal_api_key'
   export GSB_API_KEY='your_google_safe_browsing_api_key'
   ```

## Usage
To run the application, execute the following command:
```bash
python dashboard.py
```
Access the dashboard at `http://127.0.0.1:5000`.

## API Endpoints
- `GET /api/visited_sites`: Returns a JSON response with the list of visited sites and their threat verification status.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
This project is licensed under the MIT License.
