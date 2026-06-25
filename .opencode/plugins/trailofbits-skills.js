/**
 * Trail of Bits Skills plugin for OpenCode
 *
 * Auto-registers all skill directories from each plugin
 * so OpenCode discovers them without manual configuration.
 */

import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pluginsRoot = path.resolve(__dirname, '../../plugins');

function discoverSkillDirs() {
  const dirs = [];
  if (!fs.existsSync(pluginsRoot)) return dirs;

  for (const plugin of fs.readdirSync(pluginsRoot)) {
    const skillsDir = path.join(pluginsRoot, plugin, 'skills');
    if (fs.existsSync(skillsDir) && fs.statSync(skillsDir).isDirectory()) {
      dirs.push(skillsDir);
    }
  }

  return dirs;
}

export const TrailOfBitsSkills = async () => {
  return {
    // Inject skills paths into live config so OpenCode discovers
    // all Trail of Bits skills without requiring manual symlinks.
    config: async (config) => {
      config.skills = config.skills || {};
      config.skills.paths = config.skills.paths || [];

      for (const dir of discoverSkillDirs()) {
        if (!config.skills.paths.includes(dir)) {
          config.skills.paths.push(dir);
        }
      }
    },
  };
};
