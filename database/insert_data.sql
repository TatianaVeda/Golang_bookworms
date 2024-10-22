DELETE FROM post_categories;
DELETE FROM comments;
DELETE FROM likes_dislikes;
DELETE FROM posts;
DELETE FROM categories;
DELETE FROM users;
DELETE FROM comment_likes;
-- ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0; 


-- Insert data into users table
INSERT INTO users (id, email, username, password) 
VALUES 
    (1, 'ana@banana.na', 'ana', '$2a$10$qbhPlUJoTbgRUatWdMq9m.iVdIyuYm1sWQMytH86EZxwdtkqHYNTa'), 
    (2, 'user1@example.com', 'user1', 'hashedpassword2'),
    (3, 'user2@example.com', 'user2', 'hashedpassword3');  

-- Insert data into categories table
INSERT INTO categories (id, name) 
VALUES 
    (1, 'Technology'),
    (2, 'Literature'),
    (3, 'Music'),
    (4, 'Art'); 

-- Insert data into posts table
INSERT INTO posts (id, title, body, user_id, category_id) 
VALUES 
    (1, 'First Post on Technology', 'This is a post about technology.', 1, 1),
    (2, 'Exploring Literature', 'A post discussing modern literature.', 1, 2),
    (3, 'The Beauty of Classical Music', 'This post is all about classical music.', 2, 3),
    (4, 'Thinking about pipes', 'A post discussing pipes.', 1, 2);

-- Insert data into post_categories table
INSERT INTO post_categories (post_id, category_id) VALUES (1, 2);
INSERT INTO post_categories (post_id, category_id) VALUES (1, 3);


-- Insert data into comments table
INSERT INTO comments (id, body, post_id, user_id) 
VALUES 
    (1, 'Great post! I love technology too.', 1, 1),
    (2, 'I disagree with some points.', 2, 1),
    (3, 'Amazing read on classical music! ana would approve', 3, 1),
    (4, 'comment some!', 4, 1);

-- Insert data into likes_dislikes table (posts)
INSERT INTO likes_dislikes (user_id, post_id, like_type) 
VALUES 
    (1, 1, 1),  -- Ana likes 1st post
    (2, 2, 1),  -- user2 likes second post
    (1, 3, -1), -- Ana dislikes the 3rd post
    (3, 4, 1); -- Ana likes 4th post

-- Insert data into comment_likes table (comments)
INSERT INTO comment_likes (id, user_id, comment_id, like) 
VALUES 
    (1, 1, 1, 1),  -- Ana likes first comment
    (2, 2, 2, 1),  -- user1 likes second comment
    (3, 1, 3, 1);  -- Ana likes third comment
