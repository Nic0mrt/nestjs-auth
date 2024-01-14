-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "email" VARCHAR(65) NOT NULL,
    "password" VARCHAR(65) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

--insert root admin
INSERT INTO "User" ("email", "password", "role") VALUES ('admin@example.com', 'securepassword', 'ADMIN');

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
