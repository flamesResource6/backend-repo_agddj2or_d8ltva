# MediCare Plus – Backend API

This FastAPI service powers the MediCare Plus web app with authentication, role-based access, doctor/service directories, appointments, secure messages, ratings, and medical reports.

Key endpoints:
- Auth: register, token
- Doctors: create, list, search, ratings aggregation
- Services: create, list, search
- Appointments: book, list by role
- Messages: send, list per thread or inbox
- Reports: create (doctor), list (patient/doctor)
- Admin stats: collection counters

Security & data:
- JWT-based auth (OAuth2 password flow)
- BCrypt password hashing
- MongoDB persistence with helpers

Use `/test` to verify DB connectivity.
