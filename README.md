# Blood Donation Support System

This is a Spring Boot project for Blood Donation Support System, providing user registration, authentication, and blood donation management.

---

## 🔧 Technologies Used

- Java 21+
- Spring Boot 3.x
- Spring Security
- Spring Data JPA
- TestNG for unit testing
- Mockito for mocking
- Maven for build & dependency management
- GitHub Actions for CI/CD

---

## ⚙️ Running the project

### 1️⃣ Prerequisites

- JDK 21+
- Maven 3.8+
- Database: SQL Server (or any compatible DB)

### 2️⃣ Run locally

#### Build the project
mvn clean install

#### Run the application
mvn spring-boot:run


## ⚙️ Running Tests
The project uses TestNG and Mockito for unit testing.

mvn -Dtest=AuthAccountServiceTest test

## CI/CD with GitHub Actions
This project includes a simple CI pipeline that automatically:

Builds the project

Runs unit tests on every push and pull request to main or master.

You can find the GitHub Actions workflow file at:
.github/workflows/ci.yml

## Future Improvements
Add integration tests.

Add full deployment pipeline (CD).

Add Docker support.

Add monitoring and logging.

### Connect me via: pduc2200@gmail.com

#### &#169; 2025

