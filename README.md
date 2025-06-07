# 🔐 Auth Service  
### *User Authentication and JWT Token Provider*

This project is the **Auth Service** responsible for user registration, login, and JWT token generation to secure access through the API Gateway.

---

## 🔧 **Key Features**
- ✅ User Registration and Login  
- ✅ JWT Token Generation for Authentication  
- ✅ Token Refresh Support  
- ✅ Stateless and Secure Authentication Flow  

---

## 🔗 **Integration with API Gateway**

The service generates JWT tokens which are validated by the API Gateway to control access to other microservices.

---

## 🚀 **Endpoints Overview**

| Method | Endpoint                          | Description                 |
|--------|---------------------------------|-----------------------------|
| POST   | `/api/auth/register`             | User registration           |
| POST   | `/api/auth/login`                | User login                  |
| POST   | `/api/auth/refresh-token`        | Refresh JWT token           |

---

## 📖 **Swagger UI**

You can explore the API documentation at:  
`http://localhost:{port}/api/auth/swagger-ui.html`

---

## ⚙️ **Technologies**

- Spring Boot  
- Spring Security  
- JWT  
- MongoDB  

---
