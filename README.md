Introduction
This project was conducted to explore the TLS protocol, specifically investigating how using the available Ciphers can be used to identify the application that initiated the request.

Findings
Overall this project was a success. Using the available ciphers provides an additional data-point to identify the application initiating the connection. Applications of this technology would be to prevent unwanted connections (botting or denail of service attacks).

Whats next
Creating a NGINX plugin that will make integrating this into a existing codebase easier.

References
https://tls12.xargs.org/ (TLS handshake overview byte per byte)
# tls-parser
