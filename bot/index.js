require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder } = require('discord.js');
const fetch = require('node-fetch');

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

const API = process.env.API_URL || 'http://localhost:3000';
const ADMIN_SECRET = process.env.ADMIN_SECRET;

if (!process.env.DISCORD_TOKEN || !process.env.GUILD_ID || !process.env.ROLE_ID || !ADMIN_SECRET) {
  console.error('❌ Missing DISCORD_TOKEN / GUILD_ID / ROLE_ID / ADMIN_SECRET');
  process.exit(1);
}

const commands = [
  new SlashCommandBuilder()
    .setName('createkey')
    .setDescription('Create a new key')
    .addStringOption(o => o.setName('type').setDescription('Key type').setRequired(true)
      .addChoices(
        { name: 'FREE', value: 'FREE' },
        { name: 'PREMIUM', value: 'PREMIUM' },
        { name: 'VIP', value: 'VIP' }
      ))
    .addIntegerOption(o => o.setName('hours').setDescription('Hours valid').setRequired(true).setMinValue(1).setMaxValue(8760)),

  new SlashCommandBuilder()
    .setName('deletekey')
    .setDescription('Disable a key')
    .addStringOption(o => o.setName('code').setDescription('Key code').setRequired(true)),

  new SlashCommandBuilder()
    .setName('resethwid')
    .setDescription('Reset HWID lock')
    .addStringOption(o => o.setName('code').setDescription('Key code').setRequired(true)),

  new SlashCommandBuilder()
    .setName('keyinfo')
    .setDescription('Lookup key info')
    .addStringOption(o => o.setName('code').setDescription('Key code').setRequired(true)),

  new SlashCommandBuilder()
    .setName('blacklist')
    .setDescription('Blacklist HWID / IP / Key')
    .addStringOption(o => o.setName('type').setDescription('Type').setRequired(true)
      .addChoices(
        { name: 'HWID', value: 'hwid' },
        { name: 'IP', value: 'ip' },
        { name: 'KEY', value: 'key' }
      ))
    .addStringOption(o => o.setName('value').setDescription('Value').setRequired(true))
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false)),
].map(c => c.toJSON());

client.once('ready', async () => {
  const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
  try {
    await rest.put(Routes.applicationGuildCommands(client.user.id, process.env.GUILD_ID), { body: commands });
    console.log(`✅ Bot online as ${client.user.tag}`);
  } catch (e) {
    console.error('Command register failed:', e.message);
  }
});

async function api(endpoint, body) {
  const res = await fetch(`${API}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-admin-secret': ADMIN_SECRET
    },
    body: JSON.stringify(body)
  });
  return res.json();
}

client.on('interactionCreate', async (inter) => {
  if (!inter.isChatInputCommand()) return;

  if (!inter.member.roles.cache.has(process.env.ROLE_ID)) {
    return inter.reply({ content: '❌ Key Manager role required.', ephemeral: true });
  }

  await inter.deferReply({ ephemeral: true });

  try {
    if (inter.commandName === 'createkey') {
      const type = inter.options.getString('type');
      const hours = inter.options.getInteger('hours');
      const data = await api('/api/create', { type, hours, created_by: inter.user.id });

      if (data.success) {
        const embed = new EmbedBuilder()
          .setColor(0x00ff88)
          .setTitle('Key Created')
          .addFields(
            { name: 'Code', value: `\`${data.code}\`` },
            { name: 'Type', value: data.type, inline: true },
            { name: 'Duration', value: `${hours}h`, inline: true }
          )
          .setFooter({ text: `by ${inter.user.tag}` });
        return inter.editReply({ embeds: [embed] });
      }
      return inter.editReply(`❌ ${data.error || 'Failed'}`);
    }

    if (inter.commandName === 'deletekey') {
      const code = inter.options.getString('code');
      const data = await api('/api/delete', { code });
      return inter.editReply(data.success ? `🗑️ Disabled \`${code}\`` : `❌ ${data.error}`);
    }

    if (inter.commandName === 'resethwid') {
      const code = inter.options.getString('code');
      const data = await api('/api/reset-hwid', { code });
      return inter.editReply(data.success ? `🔄 HWID reset for \`${code}\`` : `❌ ${data.error}`);
    }

    if (inter.commandName === 'keyinfo') {
      const code = inter.options.getString('code');
      const data = await api('/api/info', { code });
      if (!data.success) return inter.editReply(`❌ ${data.error}`);

      const k = data.key;
      const embed = new EmbedBuilder()
        .setColor(k.active ? 0x00ff88 : 0xff4444)
        .setTitle(k.code)
        .addFields(
          { name: 'Type', value: k.type, inline: true },
          { name: 'Active', value: k.active ? 'Yes' : 'No', inline: true },
          { name: 'HWID', value: k.hwid || '*not locked*', inline: false },
          { name: 'Expires', value: new Date(k.expires_at).toISOString(), inline: false },
          { name: 'Uses', value: String(k.use_count || 0), inline: true },
          { name: 'Created by', value: k.created_by || '?', inline: true }
        );
      return inter.editReply({ embeds: [embed] });
    }

    if (inter.commandName === 'blacklist') {
      const type = inter.options.getString('type');
      const value = inter.options.getString('value');
      const reason = inter.options.getString('reason') || `by ${inter.user.tag}`;
      const data = await api('/api/blacklist', { type, value, reason });
      return inter.editReply(data.success ? `🚫 Blacklisted \`${value}\`` : `❌ ${data.error}`);
    }
  } catch (e) {
    console.error(e);
    return inter.editReply('❌ API error');
  }
});

client.login(process.env.DISCORD_TOKEN);
