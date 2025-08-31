{
  "version": 2,
  "builds": [
    {
      "src": "app.py",
      "use": "@vercel/python"
    },
    {
      "src": "templates/index.html",
      "use": "@vercel/static"
    }
  ],
  "routes": [
    {
      "src": "/",
      "dest": "/app.py"
    },
    {
      "src": "/api/(.*)",
      "dest": "/app.py"
    },
    {
      "src": "/(.*\\.html)",
      "dest": "/templates/$1"
    },
    {
      "src": "/(.*)",
      "dest": "/app.py"
    }
  ],
  "env": {
    "VIRUSTOTAL_API_KEY": "@virustotal_api_key",
    "PYTHON_VERSION": "3.9"
  },
  "functions": {
    "app.py": {
      "maxDuration": 10
    }
  }
}