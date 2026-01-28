-- Migration: Add index on observables.type
-- Description: Adds i_obs_type index on the type column of observables for query performance
-- Date: 2026-01-28

ALTER TABLE `observables` ADD KEY `i_obs_type` (`type`);
