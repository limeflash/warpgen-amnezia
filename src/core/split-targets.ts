// AUTO-GENERATED from the web app's server.js — do not edit by hand.
export interface SplitTarget {
  label: string;
  domains?: string[];
  cidrs?: string[];
  processes?: string[];
}

export const SPLIT_TUNNEL_TARGETS: Record<string, SplitTarget> = {
    discord: {
        label: 'Discord',
        domains: ['discord.com', 'canary.discord.com', 'ptb.discord.com', 'discord.co', 'discord.gg', 'dis.gd', 'discord.new', 'discord.store', 'discordapp.net', 'discordapp.io', 'discordcdn.com', 'api.discord.gg', 'gateway.discord.gg', 'voice.discord.gg', 'rtc.discord.gg', 'discordapp.com', 'updates.discord.com', 'dl.discordapp.net', 'dl2.discordapp.net', 'stable.dl2.discordapp.net', 'cdn.discordapp.com', 'cdn.discordapp.net', 'media.discordapp.net', 'images-ext-1.discordapp.net', 'images-ext-2.discordapp.net', 'router.discordapp.net', 'discord-attachments-uploads-prd.storage.googleapis.com', 'discord.media', 'discord.tools', 'meticulous-ingest.discord.tools', 'discordsays.com', 'best.discord.media', 'latency.discord.media', 'status.discord.com', 'status.discordapp.com', 'support.discord.com', 'support.discordapp.com', 'discordstatus.com', 'discord-activities.com', 'discordactivities.com', 'discord.design', 'discord.dev', 'discord.gift', 'discord.gifts', 'discordmerch.com', 'discordpartygames.com', 'gateway-us-east1-b.discord.gg', 'gateway-us-east1-c.discord.gg', 'gateway-us-east1-d.discord.gg'],
        cidrs: ['162.159.128.0/19', '162.159.136.0/22', '188.114.96.0/20', '104.16.0.0/13', '172.64.0.0/13', '2606:4700::/32', '2a06:98c0::/29'],
    },
    youtube: { label: 'YouTube', domains: ['youtube.com', 'www.youtube.com', 'youtu.be', 'googlevideo.com', 'i.ytimg.com', 's.ytimg.com'] },
    x_com: { label: 'X.com', domains: ['x.com', 'api.x.com', 'twitter.com', 't.co', 'pbs.twimg.com', 'video.twimg.com', 'abs.twimg.com'] },
    instagram: { label: 'Instagram', domains: ['instagram.com', 'www.instagram.com', 'ig.me', 'scontent.cdninstagram.com'] },
    twitch: { label: 'Twitch', domains: ['twitch.tv', 'www.twitch.tv', 'gql.twitch.tv', 'usher.ttvnw.net', 'static-cdn.jtvnw.net'] },
    telegram: { label: 'Telegram', domains: ['telegram.org', 't.me', 'telegram.me', 'tdesktop.com'] },
    steam: { label: 'Steam', domains: ['steampowered.com', 'store.steampowered.com', 'api.steampowered.com', 'steamcommunity.com', 'steam-chat.com', 'community.cloudflare.steamstatic.com', 'cdn.cloudflare.steamstatic.com'], processes: ['steam.exe', 'steamwebhelper.exe'] },
    faceit: { label: 'FACEIT', domains: ['faceit.com', 'www.faceit.com', 'open.faceit.com', 'api.faceit.com', 'anticheat-client.faceit.com', 'cdn.faceit.com'], cidrs: ['185.69.168.0/24', '193.41.200.0/24', '77.80.253.0/24', '77.80.254.0/24', '77.80.255.0/24', '2a05:2240::/32'], processes: ['faceit.exe', 'FaceitClient.exe'] },
    whatsapp: { label: 'WhatsApp', domains: ['whatsapp.com', 'whatsapp.net'] },
    viber: { label: 'Viber', domains: ['viber.com', 'download.cdn.viber.com', 'dl-media.viber.com'] },
    jetbrains: { label: 'JetBrains', domains: ['jetbrains.com', 'download.jetbrains.com', 'plugins.jetbrains.com', 'account.jetbrains.com'] },
    tiktok: { label: 'TikTok', domains: ['tiktok.com', 'www.tiktok.com', 'm.tiktok.com', 'tiktokv.com', 'api.tiktokv.com', 'v16-webapp.tiktok.com'] },
    ipcheck_2ip: { label: '2IP', domains: ['2ip.ru', '2ip.io', 'www.2ip.ru', 'www.2ip.io'] },
    speedtest: { label: 'Speedtest', domains: ['speedtest.com', 'speedtest.net', 'www.speedtest.net', 'ookla.com'] },
    fast_com: { label: 'Fast.com', domains: ['fast.com', 'api.fast.com', 'netflix.com', 'www.netflix.com', 'nflxvideo.net', 'assets.nflxext.com'] },
    whoer: { label: 'Whoer', domains: ['whoer.net', 'www.whoer.net'] },
    geosite_ru: {
        label: 'geosite:ru (core)',
        domains: [
            'yandex.ru', 'ya.ru', 'vk.com', 'mail.ru', 'ok.ru', 'dzen.ru', 'rutube.ru', 'avito.ru', 'gosuslugi.ru',
            'sberbank.ru', 'alfabank.ru', 'tbank.ru', 'vtb.ru', 'ozon.ru', 'wildberries.ru', 'cdek.ru', 'pochta.ru',
            'rbc.ru', 'lenta.ru', 'gazeta.ru', 'ria.ru', 'tass.ru', 'kommersant.ru', 'championat.com', 'sports.ru',
            'kinopoisk.ru', 'ivi.ru', 'okko.tv', 'yoomoney.ru', 'qiwi.com', 'consultant.ru', 'garant.ru',
            'nalog.gov.ru', 'mos.ru', 'moex.com', 'hh.ru', '2gis.ru', 'pikabu.ru', 'habr.com', 'yaplakal.com',
        ],
    },
    apex_legends: { label: 'Apex Legends', domains: ['apexlegends.com', 'www.playapex.com', 'respawn.com', 'ea.com', 'www.ea.com', 'origin.com', 'accounts.ea.com', 'gateway.ea.com', 'api1.origin.com', 'download.dm.origin.com', 'origin-a.akamaihd.net'], processes: ['r5apex.exe', 'EADesktop.exe'] },
    ea_app: { label: 'EA App', domains: ['ea.com', 'www.ea.com', 'origin.com', 'accounts.ea.com', 'gateway.ea.com', 'api1.origin.com', 'download.dm.origin.com', 'origin-a.akamaihd.net', 'eaassets-a.akamaihd.net'], processes: ['EADesktop.exe', 'EALauncher.exe', 'EADM.exe'] },
    battle_net: { label: 'Battle.net', domains: ['battle.net', 'www.battle.net', 'blizzard.com', 'www.blizzard.com', 'us.patch.battle.net', 'eu.patch.battle.net', 'blzddist1-a.akamaihd.net'], processes: ['Battle.net.exe', 'BlizzardBrowserHelper.exe'] },
    cs2: { label: 'CS2', domains: ['steampowered.com', 'store.steampowered.com', 'api.steampowered.com', 'steamcommunity.com', 'steam-chat.com', 'community.cloudflare.steamstatic.com', 'cdn.cloudflare.steamstatic.com', 'valvesoftware.com', 'www.valvesoftware.com', 'cm0.steampowered.com'], cidrs: ['45.121.184.0/22', '63.150.138.0/24', '103.10.124.0/23', '103.28.54.0/23', '146.66.152.0/21', '155.133.224.0/19', '162.254.192.0/21', '185.25.180.0/22', '190.216.121.0/24', '190.217.33.0/24', '192.69.96.0/22', '205.196.6.0/24', '208.64.200.0/22', '208.78.164.0/22'], processes: ['cs2.exe'] },
    hearthstone: { label: 'Hearthstone', domains: ['battle.net', 'www.battle.net', 'blizzard.com', 'www.blizzard.com', 'us.patch.battle.net', 'eu.patch.battle.net', 'blzddist1-a.akamaihd.net'], processes: ['Hearthstone.exe'] },
    pubg: { label: 'PUBG', domains: ['pubg.com', 'www.pubg.com', 'api.pubg.com', 'accounts.pubg.com', 'krafton.com', 'www.krafton.com', 'pubgmobile.com', 'www.pubgmobile.com', 'steamcdn-a.akamaihd.net'], processes: ['TslGame.exe', 'TslGame-EAC.exe'] },
    chatgpt: {
        label: 'ChatGPT (OpenAI)',
        domains: [
            'openai.com', 'www.openai.com', 'api.openai.com', 'auth.openai.com',
            'cdn.openai.com', 'platform.openai.com', 'help.openai.com', 'labs.openai.com',
            'chatgpt.com', 'chat.openai.com', 'oaistatic.com', 'oaiusercontent.com',
            'openaiapi-site.azureedge.net', 'sora.com', 'operator.chatgpt.com',
        ],
        cidrs: ['104.16.0.0/13', '172.64.0.0/13', '188.114.96.0/20', '2606:4700::/32'],
    },
    claude_ai: {
        label: 'Claude (Anthropic)',
        domains: [
            'anthropic.com', 'www.anthropic.com', 'api.anthropic.com',
            'console.anthropic.com', 'claude.ai', 'www.claude.ai', 'userprompt.com',
        ],
        cidrs: ['104.16.0.0/13', '172.64.0.0/13', '188.114.96.0/20', '2606:4700::/32'],
    },
    gemini: {
        label: 'Gemini (Google AI)',
        domains: [
            'gemini.google.com', 'aistudio.google.com', 'ai.google.dev', 'ai.google',
            'generativelanguage.googleapis.com', 'vertexai.googleapis.com',
            'makersuite.google.com', 'deepmind.com', 'www.deepmind.com',
            'notebooklm.google.com', 'labs.google',
        ],
        cidrs: ['142.250.0.0/15', '172.217.0.0/16', '216.58.0.0/15', '74.125.0.0/16', '2607:f8b0::/32'],
    },
    grok: {
        label: 'Grok (xAI)',
        domains: ['x.ai', 'grok.com', 'api.x.ai', 'accounts.x.ai'],
        cidrs: ['104.21.0.0/16', '172.67.0.0/16', '188.114.96.0/20', '2606:4700::/32'],
    },
};
