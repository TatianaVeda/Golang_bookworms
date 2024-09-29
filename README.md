

# __Literary Lions Forum__

## Introduction
The Literary Lions Forum is designed to help book club enthusiasts to engage in meaningful discussions, share insights, and explore deeper literary themes. Users can create posts, leave comments, categorize discussions, like/dislike content, and filter posts. The forum utilized SQLite as the database, and is containerized using Docker.

## Features

### User Registration and Authentication:

- Users can register with a unique email, username, and password.
- Login is based on email and password.
- Session management is handled using cookies.
#### Passwords are stored securely using encryption.

### Database interaction:
User registration data is stored in forum.db.
Interaction with the database is out of using SQL queries SELECT, CREATE and INSERT.
#### Database Schema
consists of the following tables:
- Users: Stores user information (email, username, password hash).
- Posts: Contains posts made by users.
- Comments: Stores comments on posts.
- Categories: Defines categories for posts (Literature, Poetry, Non-fiction, Short Stories).

### Post and Comment System:

Registered users can create posts and comments.
Posts can be associated with specific categories (Literature, Poetry, Non-fiction, Short Stories).
Only registered users can create, like or dislike posts and comments.
The number of likes/dislikes is visible to users.



## Project Structure
![pic of structure](/image.png "Picture of structure")

literary-lions-forum/
│
├── main.go                      # Application entry point
│                
├── controllers/                 # Application logic
│   ├── auth.go/                 # Authentication and session management
│   ├── post.go/                 # Post, comment and categories management
│ 
│── database/                    # Database models (Users, Posts, Categories, Comments)
│   ├── db.go                    # SQLite interaction and schema
│
│── forum.db                     # Database storage
│
├── static/                      # Static style files (CSS, images)
│   ├── images/lion-icon.png 
│   ├── home.css
│   ├── modal.css     
│
├── views/                       # HTML templates
│
├── Dockerfile                   # Dockerfile for containerizing the app
├── .dockerignore                # File for ignoring while containerizing the app
│
│
├── cookies.txt                  ???  
│
├── .idea/                       ??? 
│
├── go.sum                      # Go modules file for dependencies
├── go.mod                  
└── README.md                   # Project documentation

### Technologies & Prerequisites
- Backend: Go (Golang 1.20 or later)
- Database: SQLite with go-sqlite3 driver
- Frontend: HTML, CSS, Go
- Containerization: Docker

## Getting Started

### Installation
Clone the repository:
```
git clone https://gitea.koodsisu.fi/juliageorgieva/literary-lions
cd literary-lions
```

Install Go dependencies if necessary:
``` 
go mod tidy
```

Initialize SQLite database regarding https://pkg.go.dev/github.com/mattn/go-sqlite3

### Dockerization
Follow the steps below to set up Docker, build the Docker image, run the container, and maintains a clean environment. 

1. Install Docker
Before you begin, ensure that Docker is installed on your machine. Download Docker Desktop from [the Docker website.](https://docs.docker.com/get-started/get-docker/). If you use WSL: https://docs.docker.com/desktop/wsl/.

* For Windows: After installation, start Docker Desktop and ensure it is running.
* For macOS: Open the downloaded .dmg file and drag Docker to your Applications folder, launch and ensure it is running. 
* For Linux: Follow the official Docker installation guide for your distribution: https://docs.docker.com/desktop/install/linux/

Start the Docker service:
```
sudo systemctl start docker
```
Ensure Docker is running:
```
systemctl status docker
```
2. Navigate to the project directory and build the Docker image:
```
docker build -t lions-forum-image .
```
3. Start the container using the built image:
```
docker run -d -p 8080:8080 -v lions_volume:/literary-lions/ --name lions-forum lions-forum-image
<!-- docker run -p 8080:8080 -v lions_db --name lions literary-lions-image
docker run -p 8080:8080 -v lions_db:/app/data --name lions literary-lions-image -->
```
This command runs a container named <my-container> from the <my-image>,  mapping port 8080 on the host to port 8080 on the container.
The application will be available at http://localhost:8080.

4. Verify Container Operation. To verify that the container is running:
```
docker ps
``` 
Lists all running containers. 
```
docker images
```
Shows all images. You can check the logs of the running container:
```
docker logs lions-forum
```
5. To keep your Docker environment clean, remove unused objects.
To stop container:
```
docker stop container_ID
```
Remove stopped containers: 
```
docker rm -f <container_name_or_id>
``` 
Remove image: 
```
docker rmi <image_name_or_id>
docker image prune -a -f
``` 
for all unused images.

Remove unused volumes:
```
docker volume prune -f
```
Remove unused networks: 
```
docker network prune -f
```
Full system cleanup (optional): 
```
docker system prune -a --volumes -f
```
This command removes all unused containers, images, volumes, and networks, providing a comprehensive cleanup.

6. Check Disk Usage:
```
docker system df
```
to get a general idea of ​​how much space images, containers, networks, and volumes are taking up.


## Usage

Once the forum is up and running:

1. Register a new account.
1. Log in to create posts and comments.
1. Browse the forum by posts and interact with other users by likes and comments.
1. Filter posts by different categories and participate in discussions.

#### Future Enhancements
- Search functionality: Add a search bar to allow users to search for specific posts or comments.
- User profile page: Add a page where users can view their posts, liked posts, and personal information.
- File uploads: Allow users to upload images or other files in their posts and comments.

### Contributors:

Julia Georgieva Georgieva, Mariia Melnikova, Tatiana Vedishcheva.
Hit us up in Discord if you have any questions!

