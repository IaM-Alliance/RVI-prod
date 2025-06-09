# Reverse Proxy (Nginx Proxy Manager) Setup for Docker Deployment

This document provides instructions for Nginx Proxy Manager settings when deploying this app as a Docker compose project.

## Prerequisites

- Nginx Proxy Manager (NPM) running on the same host as the Docker for this app
- NPM can be included in the same docker-compose.yml as part of project
- NPM usage seems to work best though if you set Network_Mode: host 

## NPM settings

- Follow the NPM installation and setup guide
- Create a new proxy host, set it up with the URL
- It will be an http forward, with the URL field set to the public IP address of the host, to port 5000
- Go over to the SSL tab and pick the appropriate option for SSL certificates 
- Despite it being an HTTP forward, you will still have an SSL-secured connection
- You can use one of the DNS challenge plugins that are built-in, or if you have configured DNS records to point to the NPM (and this app's) host, then the standard option for new SSL certificates will be quickest

