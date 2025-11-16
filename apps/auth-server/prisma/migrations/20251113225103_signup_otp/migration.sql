/*
  Warnings:

  - A unique constraint covering the columns `[email]` on the table `SignupVerification` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "SignupVerification_email_key" ON "SignupVerification"("email");
