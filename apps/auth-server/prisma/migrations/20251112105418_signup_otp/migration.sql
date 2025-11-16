-- CreateTable
CREATE TABLE "SignupVerification" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SignupVerification_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SignupVerification_email_idx" ON "SignupVerification"("email");
