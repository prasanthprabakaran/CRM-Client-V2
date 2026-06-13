import request from 'supertest'
import express from 'express'
import mongoose from 'mongoose'
import cookieParser from 'cookie-parser'
import * as dotenv from 'dotenv'
dotenv.config()

import { connectTestDB, disconnectTestDB } from './setup.js'
import { authRouter } from '../routes/authRoutes.js'
import errorHandler from '../middleware/errorHandler.js'
import User from '../models/User.js'
import bcrypt from 'bcrypt'

const app = express()
app.use(express.json())
app.use(cookieParser())
app.use('/auth', authRouter)
app.use(errorHandler)

beforeAll(async () => {
    await connectTestDB()

    // Seed a test user
    const salt = await bcrypt.genSalt(10)
    const hashedPwd = await bcrypt.hash('password123', salt)
    await User.create({
        username: 'testuser',
        firstname: 'Test',
        lastname: 'User',
        email: 'test@example.com',
        password: hashedPwd,
        active: true,
        roles: ['Employee']
    })
})

afterAll(async () => {
    await disconnectTestDB()
})

describe('POST /auth', () => {
    it('should login with valid credentials and return accessToken', async () => {
        const res = await request(app)
            .post('/auth')
            .send({ username: 'testuser', password: 'password123' })

        expect(res.statusCode).toBe(200)
        expect(res.body).toHaveProperty('accessToken')
    })

    it('should return 401 with wrong password', async () => {
        const res = await request(app)
            .post('/auth')
            .send({ username: 'testuser', password: 'wrongpassword' })

        expect(res.statusCode).toBe(401)
    })

    it('should return 400 when fields are missing', async () => {
        const res = await request(app)
            .post('/auth')
            .send({ username: 'testuser' })

        expect(res.statusCode).toBe(400)
        expect(res.body).toHaveProperty('errors')
    })

    it('should return 401 for non-existent user', async () => {
        const res = await request(app)
            .post('/auth')
            .send({ username: 'nobody', password: 'password123' })

        expect(res.statusCode).toBe(401)
    })
})

describe('GET /auth/refresh', () => {
    it('should return 401 when no cookie is present', async () => {
        const res = await request(app).get('/auth/refresh')
        expect(res.statusCode).toBe(401)
    })
})

describe('POST /auth/logout', () => {
    it('should return 204 when no cookie present', async () => {
        const res = await request(app).post('/auth/logout')
        expect(res.statusCode).toBe(204)
    })

    it('should clear cookie and return success message', async () => {
        const loginRes = await request(app)
            .post('/auth')
            .send({ username: 'testuser', password: 'password123' })

        const cookie = loginRes.headers['set-cookie']

        const res = await request(app)
            .post('/auth/logout')
            .set('Cookie', cookie)

        expect(res.statusCode).toBe(200)
        expect(res.body.message).toBe('Cookie cleared')
    })
})

describe('POST /auth/forgetpassword', () => {
    it('should return 400 when email is missing', async () => {
        const res = await request(app)
            .post('/auth/forgetpassword')
            .send({})

        expect(res.statusCode).toBe(400)
        expect(res.body).toHaveProperty('errors')
    })

    it('should return 400 when email format is invalid', async () => {
        const res = await request(app)
            .post('/auth/forgetpassword')
            .send({ email: 'notanemail' })

        expect(res.statusCode).toBe(400)
        expect(res.body).toHaveProperty('errors')
    })

    it('should return 404 when email does not exist', async () => {
        const res = await request(app)
            .post('/auth/forgetpassword')
            .send({ email: 'unknown@example.com' })

        expect(res.statusCode).toBe(404)
    })
})