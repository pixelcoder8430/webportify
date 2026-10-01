const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 5000;

const JWT_SECRET =
    process.env.JWT_SECRET || "webportify-development-secret-change-this";


// ======================================================
// BASIC SERVER SETTINGS
// ======================================================

app.use(cors());

app.use(express.json({
    limit: "2mb"
}));


// ======================================================
// DATABASE SETUP
// ======================================================

const dataFolder = path.join(__dirname, "data");

if (!fs.existsSync(dataFolder)) {
    fs.mkdirSync(dataFolder, {
        recursive: true
    });
}

const dbPath = path.join(dataFolder, "webportify.db");

const db = new Database(dbPath);

db.pragma("foreign_keys = ON");


// ======================================================
// DATABASE TABLES
// ======================================================

db.exec(`
    
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        website_type TEXT DEFAULT '',
        purpose TEXT DEFAULT '',
        features TEXT DEFAULT '',
        reference TEXT DEFAULT '',
        requirements TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS developers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        phone TEXT DEFAULT '',
        skills TEXT DEFAULT '',
        portfolio TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        customer_id INTEGER NOT NULL,
        developer_id INTEGER,
        order_id INTEGER,

        website_type TEXT DEFAULT '',
        purpose TEXT DEFAULT '',
        features TEXT DEFAULT '',
        reference TEXT DEFAULT '',
        requirements TEXT DEFAULT '',

        status TEXT NOT NULL DEFAULT 'pending',

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (customer_id)
            REFERENCES customers(id)
            ON DELETE CASCADE,

        FOREIGN KEY (developer_id)
            REFERENCES developers(id)
            ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        customer_id INTEGER NOT NULL,
        developer_id INTEGER,

        website_type TEXT DEFAULT '',
        purpose TEXT DEFAULT '',
        features TEXT DEFAULT '',
        reference TEXT DEFAULT '',
        requirements TEXT DEFAULT '',

        items_json TEXT DEFAULT '[]',

        total REAL DEFAULT 0,

        status TEXT NOT NULL DEFAULT 'pending',

        progress INTEGER NOT NULL DEFAULT 0,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (customer_id)
            REFERENCES customers(id)
            ON DELETE CASCADE,

        FOREIGN KEY (developer_id)
            REFERENCES developers(id)
            ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        order_id INTEGER NOT NULL UNIQUE,
        customer_id INTEGER NOT NULL,
        developer_id INTEGER NOT NULL,

        status TEXT NOT NULL DEFAULT 'active',

        progress INTEGER NOT NULL DEFAULT 0,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (order_id)
            REFERENCES orders(id)
            ON DELETE CASCADE,

        FOREIGN KEY (customer_id)
            REFERENCES customers(id)
            ON DELETE CASCADE,

        FOREIGN KEY (developer_id)
            REFERENCES developers(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        customer_id INTEGER NOT NULL,
        developer_id INTEGER NOT NULL,

        request_id INTEGER,

        sender_role TEXT NOT NULL,

        message TEXT NOT NULL,

        is_read INTEGER NOT NULL DEFAULT 0,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (customer_id)
            REFERENCES customers(id)
            ON DELETE CASCADE,

        FOREIGN KEY (developer_id)
            REFERENCES developers(id)
            ON DELETE CASCADE,

        FOREIGN KEY (request_id)
            REFERENCES requests(id)
            ON DELETE SET NULL
    );

`);


// ======================================================
// HELPER FUNCTIONS
// ======================================================

function normalizeEmail(email) {
    return String(email || "")
        .trim()
        .toLowerCase();
}


function createToken(user) {

    return jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}


function cleanUser(user) {

    if (!user) {
        return null;
    }

    return {
        id: user.id,
        name: user.name,
        email: user.email
    };
}


function getTokenFromRequest(req) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return null;
    }

    if (!authHeader.startsWith("Bearer ")) {
        return null;
    }

    return authHeader.substring(7);
}


// ======================================================
// AUTHENTICATION MIDDLEWARE
// ======================================================

function authenticate(req, res, next) {

    const token = getTokenFromRequest(req);

    if (!token) {

        return res.status(401).json({
            success: false,
            message: "Authentication required."
        });

    }

    try {

        const decoded = jwt.verify(
            token,
            JWT_SECRET
        );

        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message: "Invalid or expired token."
        });

    }
}


function requireRole(role) {

    return function (req, res, next) {

        if (!req.user || req.user.role !== role) {

            return res.status(403).json({
                success: false,
                message: "You do not have permission to access this resource."
            });

        }

        next();
    };
}


// ======================================================
// VALIDATION
// ======================================================

function validatePassword(password) {

    return (
        typeof password === "string" &&
        password.length >= 6
    );
}


function validateEmail(email) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


// ======================================================
// HEALTH CHECK
// ======================================================

app.get("/", (req, res) => {

    res.json({
        success: true,
        message: "Webportify backend is running."
    });

});


app.get("/api/health", (req, res) => {

    res.json({
        success: true,
        message: "Webportify backend is running.",
        database: "connected"
    });

});


// ======================================================
// CUSTOMER REGISTRATION
// ======================================================

app.post(
    "/api/auth/customer/register",
    async (req, res) => {

        try {

            const {
                name,
                email,
                password,
                websiteType = "",
                purpose = "",
                features = "",
                reference = "",
                requirements = ""
            } = req.body;

            const cleanName = String(name || "").trim();
            const cleanEmail = normalizeEmail(email);

            if (!cleanName) {

                return res.status(400).json({
                    success: false,
                    message: "Name is required."
                });

            }

            if (!validateEmail(cleanEmail)) {

                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid email address."
                });

            }

            if (!validatePassword(password)) {

                return res.status(400).json({
                    success: false,
                    message: "Password must contain at least 6 characters."
                });

            }

            const existingCustomer = db
                .prepare(`
                    SELECT id
                    FROM customers
                    WHERE email = ?
                `)
                .get(cleanEmail);

            if (existingCustomer) {

                return res.status(409).json({
                    success: false,
                    message: "A customer with this email already exists."
                });

            }

            const passwordHash = await bcrypt.hash(
                password,
                12
            );

            const result = db
                .prepare(`
                    INSERT INTO customers
                    (
                        name,
                        email,
                        password_hash,
                        website_type,
                        purpose,
                        features,
                        reference,
                        requirements
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `)
                .run(
                    cleanName,
                    cleanEmail,
                    passwordHash,
                    String(websiteType),
                    String(purpose),
                    String(features),
                    String(reference),
                    String(requirements)
                );

            const customer = db
                .prepare(`
                    SELECT *
                    FROM customers
                    WHERE id = ?
                `)
                .get(result.lastInsertRowid);

            const token = createToken({
                id: customer.id,
                email: customer.email,
                role: "customer"
            });

            res.status(201).json({
                success: true,
                message: "Customer account created successfully.",
                token,
                user: cleanUser(customer),
                role: "customer"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Customer registration failed."
            });

        }

    }
);


// ======================================================
// CUSTOMER LOGIN
// ======================================================

app.post(
    "/api/auth/customer/login",
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;

            const cleanEmail = normalizeEmail(email);

            if (!validateEmail(cleanEmail) || !password) {

                return res.status(400).json({
                    success: false,
                    message: "Email and password are required."
                });

            }

            const customer = db
                .prepare(`
                    SELECT *
                    FROM customers
                    WHERE email = ?
                `)
                .get(cleanEmail);

            if (!customer) {

                return res.status(401).json({
                    success: false,
                    message: "Invalid email or password."
                });

            }

            const passwordCorrect =
                await bcrypt.compare(
                    password,
                    customer.password_hash
                );

            if (!passwordCorrect) {

                return res.status(401).json({
                    success: false,
                    message: "Invalid email or password."
                });

            }

            const token = createToken({
                id: customer.id,
                email: customer.email,
                role: "customer"
            });

            res.json({
                success: true,
                message: "Customer login successful.",
                token,
                user: cleanUser(customer),
                role: "customer"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Customer login failed."
            });

        }

    }
);


// ======================================================
// DEVELOPER REGISTRATION
// ======================================================

app.post(
    "/api/auth/developer/register",
    async (req, res) => {

        try {

            const {
                name,
                email,
                password,
                phone = "",
                skills = "",
                portfolio = ""
            } = req.body;

            const cleanName = String(name || "").trim();
            const cleanEmail = normalizeEmail(email);

            if (!cleanName) {

                return res.status(400).json({
                    success: false,
                    message: "Name is required."
                });

            }

            if (!validateEmail(cleanEmail)) {

                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid email address."
                });

            }

            if (!validatePassword(password)) {

                return res.status(400).json({
                    success: false,
                    message: "Password must contain at least 6 characters."
                });

            }

            const existingDeveloper = db
                .prepare(`
                    SELECT id
                    FROM developers
                    WHERE email = ?
                `)
                .get(cleanEmail);

            if (existingDeveloper) {

                return res.status(409).json({
                    success: false,
                    message: "A developer with this email already exists."
                });

            }

            const passwordHash = await bcrypt.hash(
                password,
                12
            );

            const result = db
                .prepare(`
                    INSERT INTO developers
                    (
                        name,
                        email,
                        password_hash,
                        phone,
                        skills,
                        portfolio
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                `)
                .run(
                    cleanName,
                    cleanEmail,
                    passwordHash,
                    String(phone),
                    String(skills),
                    String(portfolio)
                );

            const developer = db
                .prepare(`
                    SELECT *
                    FROM developers
                    WHERE id = ?
                `)
                .get(result.lastInsertRowid);

            const token = createToken({
                id: developer.id,
                email: developer.email,
                role: "developer"
            });

            res.status(201).json({
                success: true,
                message: "Developer account created successfully.",
                token,
                user: cleanUser(developer),
                role: "developer"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Developer registration failed."
            });

        }

    }
);


// ======================================================
// DEVELOPER LOGIN
// ======================================================

app.post(
    "/api/auth/developer/login",
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;

            const cleanEmail = normalizeEmail(email);

            if (!validateEmail(cleanEmail) || !password) {

                return res.status(400).json({
                    success: false,
                    message: "Email and password are required."
                });

            }

            const developer = db
                .prepare(`
                    SELECT *
                    FROM developers
                    WHERE email = ?
                `)
                .get(cleanEmail);

            if (!developer) {

                return res.status(401).json({
                    success: false,
                    message: "Invalid email or password."
                });

            }

            const passwordCorrect =
                await bcrypt.compare(
                    password,
                    developer.password_hash
                );

            if (!passwordCorrect) {

                return res.status(401).json({
                    success: false,
                    message: "Invalid email or password."
                });

            }

            const token = createToken({
                id: developer.id,
                email: developer.email,
                role: "developer"
            });

            res.json({
                success: true,
                message: "Developer login successful.",
                token,
                user: cleanUser(developer),
                role: "developer"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Developer login failed."
            });

        }

    }
);


// ======================================================
// CURRENT USER
// ======================================================

app.get(
    "/api/me",
    authenticate,
    (req, res) => {

        try {

            let user;

            if (req.user.role === "customer") {

                user = db
                    .prepare(`
                        SELECT
                            id,
                            name,
                            email,
                            website_type,
                            purpose,
                            features,
                            reference,
                            requirements,
                            created_at,
                            updated_at
                        FROM customers
                        WHERE id = ?
                    `)
                    .get(req.user.id);

            } else {

                user = db
                    .prepare(`
                        SELECT
                            id,
                            name,
                            email,
                            phone,
                            skills,
                            portfolio,
                            created_at,
                            updated_at
                        FROM developers
                        WHERE id = ?
                    `)
                    .get(req.user.id);

            }

            if (!user) {

                return res.status(404).json({
                    success: false,
                    message: "User not found."
                });

            }

            res.json({
                success: true,
                user,
                role: req.user.role
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load user information."
            });

        }

    }
);


// ======================================================
// CUSTOMER PROFILE UPDATE
// ======================================================

app.patch(
    "/api/customers/me",
    authenticate,
    requireRole("customer"),
    (req, res) => {

        try {

            const {
                name,
                websiteType,
                purpose,
                features,
                reference,
                requirements
            } = req.body;

            const current = db
                .prepare(`
                    SELECT *
                    FROM customers
                    WHERE id = ?
                `)
                .get(req.user.id);

            if (!current) {

                return res.status(404).json({
                    success: false,
                    message: "Customer not found."
                });

            }

            db.prepare(`
                UPDATE customers
                SET
                    name = ?,
                    website_type = ?,
                    purpose = ?,
                    features = ?,
                    reference = ?,
                    requirements = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(
                name !== undefined
                    ? String(name).trim()
                    : current.name,

                websiteType !== undefined
                    ? String(websiteType)
                    : current.website_type,

                purpose !== undefined
                    ? String(purpose)
                    : current.purpose,

                features !== undefined
                    ? String(features)
                    : current.features,

                reference !== undefined
                    ? String(reference)
                    : current.reference,

                requirements !== undefined
                    ? String(requirements)
                    : current.requirements,

                req.user.id
            );

            const updated = db
                .prepare(`
                    SELECT
                        id,
                        name,
                        email,
                        website_type,
                        purpose,
                        features,
                        reference,
                        requirements,
                        created_at,
                        updated_at
                    FROM customers
                    WHERE id = ?
                `)
                .get(req.user.id);

            res.json({
                success: true,
                message: "Customer profile updated.",
                user: updated
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not update customer profile."
            });

        }

    }
);


// ======================================================
// DEVELOPER PROFILE UPDATE
// ======================================================

app.patch(
    "/api/developers/me",
    authenticate,
    requireRole("developer"),
    (req, res) => {

        try {

            const {
                name,
                phone,
                skills,
                portfolio
            } = req.body;

            const current = db
                .prepare(`
                    SELECT *
                    FROM developers
                    WHERE id = ?
                `)
                .get(req.user.id);

            if (!current) {

                return res.status(404).json({
                    success: false,
                    message: "Developer not found."
                });

            }

            db.prepare(`
                UPDATE developers
                SET
                    name = ?,
                    phone = ?,
                    skills = ?,
                    portfolio = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(
                name !== undefined
                    ? String(name).trim()
                    : current.name,

                phone !== undefined
                    ? String(phone)
                    : current.phone,

                skills !== undefined
                    ? String(skills)
                    : current.skills,

                portfolio !== undefined
                    ? String(portfolio)
                    : current.portfolio,

                req.user.id
            );

            const updated = db
                .prepare(`
                    SELECT
                        id,
                        name,
                        email,
                        phone,
                        skills,
                        portfolio,
                        created_at,
                        updated_at
                    FROM developers
                    WHERE id = ?
                `)
                .get(req.user.id);

            res.json({
                success: true,
                message: "Developer profile updated.",
                user: updated
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not update developer profile."
            });

        }

    }
);


// ======================================================
// CREATE CUSTOMER REQUEST
// ======================================================

app.post(
    "/api/requests",
    authenticate,
    requireRole("customer"),
    (req, res) => {

        try {

            const {
                websiteType = "",
                purpose = "",
                features = "",
                reference = "",
                requirements = "",
                orderId = null
            } = req.body;

            const result = db
                .prepare(`
                    INSERT INTO requests
                    (
                        customer_id,
                        order_id,
                        website_type,
                        purpose,
                        features,
                        reference,
                        requirements
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `)
                .run(
                    req.user.id,
                    orderId,
                    String(websiteType),
                    String(purpose),
                    String(features),
                    String(reference),
                    String(requirements)
                );

            const request = db
                .prepare(`
                    SELECT *
                    FROM requests
                    WHERE id = ?
                `)
                .get(result.lastInsertRowid);

            res.status(201).json({
                success: true,
                message: "Website request submitted.",
                request
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not create website request."
            });

        }

    }
);


// ======================================================
// CUSTOMER'S REQUESTS
// ======================================================

app.get(
    "/api/requests/mine",
    authenticate,
    requireRole("customer"),
    (req, res) => {

        try {

            const requests = db
                .prepare(`
                    SELECT
                        r.*,
                        d.name AS developer_name,
                        d.email AS developer_email
                    FROM requests r

                    LEFT JOIN developers d
                        ON r.developer_id = d.id

                    WHERE r.customer_id = ?

                    ORDER BY r.created_at DESC
                `)
                .all(req.user.id);

            res.json({
                success: true,
                requests
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load requests."
            });

        }

    }
);


// ======================================================
// ALL REQUESTS FOR DEVELOPERS
// ======================================================

app.get(
    "/api/requests",
    authenticate,
    requireRole("developer"),
    (req, res) => {

        try {

            const requests = db
                .prepare(`
                    SELECT
                        r.*,

                        c.name AS customer_name,
                        c.email AS customer_email,

                        d.name AS developer_name

                    FROM requests r

                    JOIN customers c
                        ON r.customer_id = c.id

                    LEFT JOIN developers d
                        ON r.developer_id = d.id

                    ORDER BY r.created_at DESC
                `)
                .all();

            res.json({
                success: true,
                requests
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load customer requests."
            });

        }

    }
);


// ======================================================
// GET ONE REQUEST
// ======================================================

app.get(
    "/api/requests/:id",
    authenticate,
    (req, res) => {

        try {

            const requestId = Number(req.params.id);

            const request = db
                .prepare(`
                    SELECT
                        r.*,

                        c.name AS customer_name,
                        c.email AS customer_email,

                        d.name AS developer_name,
                        d.email AS developer_email

                    FROM requests r

                    JOIN customers c
                        ON r.customer_id = c.id

                    LEFT JOIN developers d
                        ON r.developer_id = d.id

                    WHERE r.id = ?
                `)
                .get(requestId);

            if (!request) {

                return res.status(404).json({
                    success: false,
                    message: "Request not found."
                });

            }

            if (
                req.user.role === "customer" &&
                request.customer_id !== req.user.id
            ) {

                return res.status(403).json({
                    success: false,
                    message: "You cannot view this request."
                });

            }

            res.json({
                success: true,
                request
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load request."
            });

        }

    }
);


// ======================================================
// DEVELOPER ACCEPT / REJECT REQUEST
// ======================================================

app.patch(
    "/api/requests/:id",
    authenticate,
    requireRole("developer"),
    (req, res) => {

        try {

            const requestId = Number(req.params.id);

            const {
                status
            } = req.body;

            const allowedStatuses = [
                "pending",
                "accepted",
                "rejected"
            ];

            if (!allowedStatuses.includes(status)) {

                return res.status(400).json({
                    success: false,
                    message: "Invalid request status."
                });

            }

            const request = db
                .prepare(`
                    SELECT *
                    FROM requests
                    WHERE id = ?
                `)
                .get(requestId);

            if (!request) {

                return res.status(404).json({
                    success: false,
                    message: "Request not found."
                });

            }

            const updateRequest = db.transaction(() => {

                db.prepare(`
                    UPDATE requests
                    SET
                        status = ?,
                        developer_id = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `).run(
                    status,
                    status === "accepted"
                        ? req.user.id
                        : request.developer_id,
                    requestId
                );

                if (
                    status === "accepted" &&
                    request.order_id
                ) {

                    const order = db
                        .prepare(`
                            SELECT *
                            FROM orders
                            WHERE id = ?
                        `)
                        .get(request.order_id);

                    if (order) {

                        db.prepare(`
                            UPDATE orders
                            SET
                                developer_id = ?,
                                status = 'in_progress',
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = ?
                        `).run(
                            req.user.id,
                            order.id
                        );

                        const existingProject = db
                            .prepare(`
                                SELECT id
                                FROM projects
                                WHERE order_id = ?
                            `)
                            .get(order.id);

                        if (!existingProject) {

                            db.prepare(`
                                INSERT INTO projects
                                (
                                    order_id,
                                    customer_id,
                                    developer_id,
                                    status,
                                    progress
                                )
                                VALUES (?, ?, ?, 'active', 0)
                            `).run(
                                order.id,
                                order.customer_id,
                                req.user.id
                            );

                        }

                    }

                }

            });

            updateRequest();

            const updated = db
                .prepare(`
                    SELECT *
                    FROM requests
                    WHERE id = ?
                `)
                .get(requestId);

            res.json({
                success: true,
                message: `Request ${status}.`,
                request: updated
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not update request."
            });

        }

    }
);


// ======================================================
// CREATE ORDER
// ======================================================

app.post(
    "/api/orders",
    authenticate,
    requireRole("customer"),
    (req, res) => {

        try {

            const {
                websiteType = "",
                purpose = "",
                features = "",
                reference = "",
                requirements = "",
                items = [],
                total = 0
            } = req.body;

            const createOrder = db.transaction(() => {

                const orderResult = db
                    .prepare(`
                        INSERT INTO orders
                        (
                            customer_id,
                            website_type,
                            purpose,
                            features,
                            reference,
                            requirements,
                            items_json,
                            total
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    `)
                    .run(
                        req.user.id,
                        String(websiteType),
                        String(purpose),
                        String(features),
                        String(reference),
                        String(requirements),
                        JSON.stringify(items),
                        Number(total) || 0
                    );

                const orderId = orderResult.lastInsertRowid;

                db.prepare(`
                    INSERT INTO requests
                    (
                        customer_id,
                        order_id,
                        website_type,
                        purpose,
                        features,
                        reference,
                        requirements
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `).run(
                    req.user.id,
                    orderId,
                    String(websiteType),
                    String(purpose),
                    String(features),
                    String(reference),
                    String(requirements)
                );

                return orderId;

            });

            const orderId = createOrder();

            const order = db
                .prepare(`
                    SELECT *
                    FROM orders
                    WHERE id = ?
                `)
                .get(orderId);

            res.status(201).json({
                success: true,
                message: "Order created successfully.",
                order
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not create order."
            });

        }

    }
);


// ======================================================
// CUSTOMER ORDERS
// ======================================================

app.get(
    "/api/orders/mine",
    authenticate,
    requireRole("customer"),
    (req, res) => {

        try {

            const orders = db
                .prepare(`
                    SELECT
                        o.*,
                        d.name AS developer_name,
                        d.email AS developer_email
                    FROM orders o

                    LEFT JOIN developers d
                        ON o.developer_id = d.id

                    WHERE o.customer_id = ?

                    ORDER BY o.created_at DESC
                `)
                .all(req.user.id);

            const parsedOrders = orders.map(order => ({
                ...order,
                items: JSON.parse(order.items_json || "[]")
            }));

            res.json({
                success: true,
                orders: parsedOrders
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load customer orders."
            });

        }

    }
);


// ======================================================
// DEVELOPER ORDERS
// ======================================================

app.get(
    "/api/orders",
    authenticate,
    requireRole("developer"),
    (req, res) => {

        try {

            const orders = db
                .prepare(`
                    SELECT
                        o.*,
                        c.name AS customer_name,
                        c.email AS customer_email
                    FROM orders o

                    JOIN customers c
                        ON o.customer_id = c.id

                    WHERE
                        o.developer_id = ?
                        OR o.status = 'pending'

                    ORDER BY o.created_at DESC
                `)
                .all(req.user.id);

            const parsedOrders = orders.map(order => ({
                ...order,
                items: JSON.parse(order.items_json || "[]")
            }));

            res.json({
                success: true,
                orders: parsedOrders
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load developer orders."
            });

        }

    }
);


// ======================================================
// GET ONE ORDER
// ======================================================

app.get(
    "/api/orders/:id",
    authenticate,
    (req, res) => {

        try {

            const orderId = Number(req.params.id);

            const order = db
                .prepare(`
                    SELECT
                        o.*,

                        c.name AS customer_name,
                        c.email AS customer_email,

                        d.name AS developer_name,
                        d.email AS developer_email

                    FROM orders o

                    JOIN customers c
                        ON o.customer_id = c.id

                    LEFT JOIN developers d
                        ON o.developer_id = d.id

                    WHERE o.id = ?
                `)
                .get(orderId);

            if (!order) {

                return res.status(404).json({
                    success: false,
                    message: "Order not found."
                });

            }

            if (
                req.user.role === "customer" &&
                order.customer_id !== req.user.id
            ) {

                return res.status(403).json({
                    success: false,
                    message: "You cannot view this order."
                });

            }

            if (
                req.user.role === "developer" &&
                order.developer_id !== req.user.id &&
                order.status !== "pending"
            ) {

                return res.status(403).json({
                    success: false,
                    message: "You cannot view this order."
                });

            }

            res.json({
                success: true,
                order: {
                    ...order,
                    items: JSON.parse(
                        order.items_json || "[]"
                    )
                }
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load order."
            });

        }

    }
);


// ======================================================
// DEVELOPER UPDATE ORDER
// ======================================================

app.patch(
    "/api/orders/:id",
    authenticate,
    requireRole("developer"),
    (req, res) => {

        try {

            const orderId = Number(req.params.id);

            const {
                status,
                progress
            } = req.body;

            const order = db
                .prepare(`
                    SELECT *
                    FROM orders
                    WHERE id = ?
                `)
                .get(orderId);

            if (!order) {

                return res.status(404).json({
                    success: false,
                    message: "Order not found."
                });

            }

            if (
                order.developer_id &&
                order.developer_id !== req.user.id
            ) {

                return res.status(403).json({
                    success: false,
                    message: "This order belongs to another developer."
                });

            }

            let newProgress =
                progress !== undefined
                    ? Number(progress)
                    : order.progress;

            if (!Number.isInteger(newProgress)) {
                newProgress = order.progress;
            }

            newProgress = Math.max(
                0,
                Math.min(100, newProgress)
            );

            let newStatus =
                status || order.status;

            if (newProgress >= 100) {
                newStatus = "completed";
            }

            db.prepare(`
                UPDATE orders
                SET
                    developer_id = ?,
                    status = ?,
                    progress = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(
                req.user.id,
                newStatus,
                newProgress,
                orderId
            );

            const project = db
                .prepare(`
                    SELECT *
                    FROM projects
                    WHERE order_id = ?
                `)
                .get(orderId);

            if (project) {

                const projectStatus =
                    newProgress >= 100 ||
                    newStatus === "completed"
                        ? "completed"
                        : "active";

                db.prepare(`
                    UPDATE projects
                    SET
                        status = ?,
                        progress = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `).run(
                    projectStatus,
                    newProgress,
                    project.id
                );

            }

            const updated = db
                .prepare(`
                    SELECT *
                    FROM orders
                    WHERE id = ?
                `)
                .get(orderId);

            res.json({
                success: true,
                message: "Order updated.",
                order: {
                    ...updated,
                    items: JSON.parse(
                        updated.items_json || "[]"
                    )
                }
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not update order."
            });

        }

    }
);


// ======================================================
// PROJECTS
// ======================================================

app.get(
    "/api/projects",
    authenticate,
    (req, res) => {

        try {

            const {
                status
            } = req.query;

            let projects;

            if (req.user.role === "developer") {

                if (
                    status === "active" ||
                    status === "completed"
                ) {

                    projects = db
                        .prepare(`
                            SELECT
                                p.*,

                                o.website_type,
                                o.total,
                                o.status AS order_status,

                                c.name AS customer_name,
                                c.email AS customer_email

                            FROM projects p

                            JOIN orders o
                                ON p.order_id = o.id

                            JOIN customers c
                                ON p.customer_id = c.id

                            WHERE
                                p.developer_id = ?
                                AND p.status = ?

                            ORDER BY p.updated_at DESC
                        `)
                        .all(
                            req.user.id,
                            status
                        );

                } else {

                    projects = db
                        .prepare(`
                            SELECT
                                p.*,

                                o.website_type,
                                o.total,
                                o.status AS order_status,

                                c.name AS customer_name,
                                c.email AS customer_email

                            FROM projects p

                            JOIN orders o
                                ON p.order_id = o.id

                            JOIN customers c
                                ON p.customer_id = c.id

                            WHERE p.developer_id = ?

                            ORDER BY p.updated_at DESC
                        `)
                        .all(req.user.id);

                }

            } else {

                if (
                    status === "active" ||
                    status === "completed"
                ) {

                    projects = db
                        .prepare(`
                            SELECT
                                p.*,

                                o.website_type,
                                o.total,
                                o.status AS order_status,

                                d.name AS developer_name,
                                d.email AS developer_email

                            FROM projects p

                            JOIN orders o
                                ON p.order_id = o.id

                            JOIN developers d
                                ON p.developer_id = d.id

                            WHERE
                                p.customer_id = ?
                                AND p.status = ?

                            ORDER BY p.updated_at DESC
                        `)
                        .all(
                            req.user.id,
                            status
                        );

                } else {

                    projects = db
                        .prepare(`
                            SELECT
                                p.*,

                                o.website_type,
                                o.total,
                                o.status AS order_status,

                                d.name AS developer_name,
                                d.email AS developer_email

                            FROM projects p

                            JOIN orders o
                                ON p.order_id = o.id

                            JOIN developers d
                                ON p.developer_id = d.id

                            WHERE p.customer_id = ?

                            ORDER BY p.updated_at DESC
                        `)
                        .all(req.user.id);

                }

            }

            res.json({
                success: true,
                projects
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load projects."
            });

        }

    }
);


// ======================================================
// DEVELOPER UPDATE PROJECT
// ======================================================

app.patch(
    "/api/projects/:id",
    authenticate,
    requireRole("developer"),
    (req, res) => {

        try {

            const projectId = Number(req.params.id);

            const {
                progress,
                status
            } = req.body;

            const project = db
                .prepare(`
                    SELECT *
                    FROM projects
                    WHERE id = ?
                `)
                .get(projectId);

            if (!project) {

                return res.status(404).json({
                    success: false,
                    message: "Project not found."
                });

            }

            if (
                project.developer_id !== req.user.id
            ) {

                return res.status(403).json({
                    success: false,
                    message: "This project belongs to another developer."
                });

            }

            let newProgress =
                progress !== undefined
                    ? Number(progress)
                    : project.progress;

            newProgress = Math.max(
                0,
                Math.min(100, newProgress)
            );

            let newStatus =
                status ||
                project.status;

            if (newProgress >= 100) {
                newStatus = "completed";
            }

            db.prepare(`
                UPDATE projects
                SET
                    status = ?,
                    progress = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(
                newStatus,
                newProgress,
                projectId
            );

            db.prepare(`
                UPDATE orders
                SET
                    status = ?,
                    progress = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(
                newStatus === "completed"
                    ? "completed"
                    : "in_progress",
                newProgress,
                project.order_id
            );

            const updated = db
                .prepare(`
                    SELECT *
                    FROM projects
                    WHERE id = ?
                `)
                .get(projectId);

            res.json({
                success: true,
                message: "Project updated.",
                project: updated
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not update project."
            });

        }

    }
);


// ======================================================
// MESSAGES
// ======================================================

app.get(
    "/api/messages",
    authenticate,
    (req, res) => {

        try {

            const customerIdParam =
                req.query.customerId;

            const requestIdParam =
                req.query.requestId;

            let messages;

            if (req.user.role === "customer") {

                let query = `
                    SELECT
                        m.*,

                        c.name AS customer_name,
                        d.name AS developer_name

                    FROM messages m

                    JOIN customers c
                        ON m.customer_id = c.id

                    JOIN developers d
                        ON m.developer_id = d.id

                    WHERE m.customer_id = ?
                `;

                const params = [
                    req.user.id
                ];

                if (requestIdParam) {

                    query += `
                        AND m.request_id = ?
                    `;

                    params.push(
                        Number(requestIdParam)
                    );

                }

                query += `
                    ORDER BY m.created_at ASC
                `;

                messages = db
                    .prepare(query)
                    .all(...params);

            } else {

                if (!customerIdParam) {

                    return res.status(400).json({
                        success: false,
                        message: "customerId is required for developers."
                    });

                }

                const customerId =
                    Number(customerIdParam);

                const relationship = db
                    .prepare(`
                        SELECT id
                        FROM requests
                        WHERE
                            customer_id = ?
                            AND developer_id = ?
                        LIMIT 1
                    `)
                    .get(
                        customerId,
                        req.user.id
                    );

                if (!relationship) {

                    return res.status(403).json({
                        success: false,
                        message: "You are not connected to this customer."
                    });

                }

                let query = `
                    SELECT
                        m.*,

                        c.name AS customer_name,
                        d.name AS developer_name

                    FROM messages m

                    JOIN customers c
                        ON m.customer_id = c.id

                    JOIN developers d
                        ON m.developer_id = d.id

                    WHERE
                        m.customer_id = ?
                        AND m.developer_id = ?
                `;

                const params = [
                    customerId,
                    req.user.id
                ];

                if (requestIdParam) {

                    query += `
                        AND m.request_id = ?
                    `;

                    params.push(
                        Number(requestIdParam)
                    );

                }

                query += `
                    ORDER BY m.created_at ASC
                `;

                messages = db
                    .prepare(query)
                    .all(...params);

            }

            res.json({
                success: true,
                messages
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not load messages."
            });

        }

    }
);


// ======================================================
// SEND MESSAGE
// ======================================================

app.post(
    "/api/messages",
    authenticate,
    (req, res) => {

        try {

            const {
                customerId,
                developerId,
                requestId = null,
                message
            } = req.body;

            const cleanMessage =
                String(message || "").trim();

            if (!cleanMessage) {

                return res.status(400).json({
                    success: false,
                    message: "Message cannot be empty."
                });

            }

            let finalCustomerId;
            let finalDeveloperId;

            if (req.user.role === "customer") {

                finalCustomerId =
                    req.user.id;

                finalDeveloperId =
                    Number(developerId);

                if (!finalDeveloperId) {

                    return res.status(400).json({
                        success: false,
                        message: "developerId is required."
                    });

                }

            } else {

                finalDeveloperId =
                    req.user.id;

                finalCustomerId =
                    Number(customerId);

                if (!finalCustomerId) {

                    return res.status(400).json({
                        success: false,
                        message: "customerId is required."
                    });

                }

            }

            const relationship = db
                .prepare(`
                    SELECT id
                    FROM requests
                    WHERE
                        customer_id = ?
                        AND developer_id = ?
                    LIMIT 1
                `)
                .get(
                    finalCustomerId,
                    finalDeveloperId
                );

            if (!relationship) {

                return res.status(403).json({
                    success: false,
                    message: "The customer and developer are not connected."
                });

            }

            const result = db
                .prepare(`
                    INSERT INTO messages
                    (
                        customer_id,
                        developer_id,
                        request_id,
                        sender_role,
                        message
                    )
                    VALUES (?, ?, ?, ?, ?)
                `)
                .run(
                    finalCustomerId,
                    finalDeveloperId,
                    requestId
                        ? Number(requestId)
                        : null,
                    req.user.role,
                    cleanMessage
                );

            const newMessage = db
                .prepare(`
                    SELECT *
                    FROM messages
                    WHERE id = ?
                `)
                .get(result.lastInsertRowid);

            res.status(201).json({
                success: true,
                message: "Message sent.",
                data: newMessage
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not send message."
            });

        }

    }
);


// ======================================================
// MARK MESSAGE AS READ
// ======================================================

app.patch(
    "/api/messages/:id/read",
    authenticate,
    (req, res) => {

        try {

            const messageId =
                Number(req.params.id);

            const message = db
                .prepare(`
                    SELECT *
                    FROM messages
                    WHERE id = ?
                `)
                .get(messageId);

            if (!message) {

                return res.status(404).json({
                    success: false,
                    message: "Message not found."
                });

            }

            const canRead =
                (
                    req.user.role === "customer" &&
                    message.customer_id === req.user.id
                )
                ||
                (
                    req.user.role === "developer" &&
                    message.developer_id === req.user.id
                );

            if (!canRead) {

                return res.status(403).json({
                    success: false,
                    message: "You cannot update this message."
                });

            }

            db.prepare(`
                UPDATE messages
                SET is_read = 1
                WHERE id = ?
            `).run(messageId);

            res.json({
                success: true,
                message: "Message marked as read."
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not update message."
            });

        }

    }
);


// ======================================================
// ERROR HANDLER
// ======================================================

app.use((req, res) => {

    res.status(404).json({
        success: false,
        message: "API endpoint not found."
    });

});


// ======================================================
// START SERVER
// ======================================================

app.listen(PORT, () => {

    console.log("");
    console.log("========================================");
    console.log("       WEBPORTIFY BACKEND");
    console.log("========================================");
    console.log("");
    console.log(`Server running on: http://localhost:${PORT}`);
    console.log(`Health check:      http://localhost:${PORT}/api/health`);
    console.log("");
    console.log("Database:");
    console.log(dbPath);
    console.log("");
    console.log("========================================");
    console.log("");

});