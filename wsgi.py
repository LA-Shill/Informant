# !/usr/bin/env python
# Name:     wsgi.py
# By:       LA-Shill
# Date:     21.02.2021
# Version   0.1
# -----------------------------------------------

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port='5000')