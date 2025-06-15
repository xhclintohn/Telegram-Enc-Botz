const { Telegraf, Markup } = require('telegraf');
const JavaScriptObfuscator = require('javascript-obfuscator');
const fs = require('fs');
const fetch = require('node-fetch');
const path = require('path');
const beautify = require('js-beautify').js;
const crypto = require('crypto');

// Bot token
const BOT_TOKEN = '7744703463:AAF0vasBkkkVr8ogRC2SXQs4PyBqZeo5vAw';
const bot = new Telegraf(BOT_TOKEN);
const logoUrl = 'https://files.catbox.moe/0e8nu3.jpg';
const SECRET_KEY = crypto.createHash('sha256').update('xh_clintonダ_secret').digest();

// Supported document extensions
const SUPPORTED_DOC_EXTENSIONS = ['.doc', '.docx', '.odt', '.rtf', '.txt', '.wps', '.wpd'];

// Console msg
console.log('🚀 xh_clinton ダ Obfuscator Bot starting...');
console.log('📅', new Date().toLocaleString());
console.log('🔗 Follow developer: https://github.com/xhclintohn');
console.log('📧 Telegram: @xhclintonn');


function formatMessage(text) {
    return `◈━━━━━━━━━━━━━━━━◈\n${text}\n◈━━━━━━━━━━━━━━━━◈`;
}

// Loading bar animation
async function showLoading(ctx, message, duration = 2000) {
    const frames = [
        '▰▱▱▱▱▱▱▱▱▱ 🚀',
        '▰▰▱▱▱▱▱▱▱▱ 🚀',
        '▰▰▰▱▱▱▱▱▱▱ 🚀',
        '▰▰▰▰▱▱▱▱▱▱ 🚀',
        '▰▰▰▰▰▱▱▱▱▱ 🚀',
        '▰▰▰▰▰▰▱▱▱▱ 🚀',
        '▰▰▰▰▰▰▰▱▱▱ 🚀',
        '▰▰▰▰▰▰▰▰▱▱ 🚀',
        '▰▰▰▰▰▰▰▰▰▱ 🚀',
        '▰▰▰▰▰▰▰▰▰▰ 🚀'
    ];
    let frameIndex = 0;
    const loadingMsg = await ctx.reply(formatMessage(`${message} ${frames[0]}`));
    
    const interval = setInterval(async () => {
        frameIndex = (frameIndex + 1) % frames.length;
        try {
            await ctx.telegram.editMessageText(
                ctx.chat.id,
                loadingMsg.message_id,
                null,
                formatMessage(`${message} ${frames[frameIndex]}`)
            );
        } catch (e) {
            clearInterval(interval);
        }
    }, 200);
    
    return {
        message: loadingMsg,
        stop: async () => {
            clearInterval(interval);
            try {
                await ctx.telegram.deleteMessage(ctx.chat.id, loadingMsg.message_id);
            } catch (e) {
                console.error('Error deleting message:', e);
            }
        }
    };
}

// Obfuscate JavaScript
function obfuscateCode(content) {
    const obfuscationOptions = {
        compact: true,
        controlFlowFlattening: true,
        controlFlowFlatteningThreshold: 0.8,
        deadCodeInjection: true,
        deadCodeInjectionThreshold: 0.6,
        identifierNamesGenerator: 'mangled',
        identifierNamesPrefix: 'xh_clintonダxh_clintonダ',
        renameGlobals: true,
        stringArray: true,
        stringArrayEncoding: ['base64'],
        unicodeEscapeSequence: true,
        transformObjectKeys: true,
        seed: 'xh_clintonダ'
    };
    
    const obfuscated = JavaScriptObfuscator.obfuscate(content, obfuscationOptions);
    let code = obfuscated.getObfuscatedCode();
    const lines = code.split('\n');
    let finalCode = `// Secured by xh_clintonダ\n`;
    finalCode += `// xh_clintonダ Protection Layer\n`;
    
    lines.forEach((line, index) => {
        finalCode += line + '\n';
        if (index % 2 === 0) {
            finalCode += `// xh_clintonダ Security Mark ${index}\n`;
        }
        if (index % 4 === 0) {
            finalCode += `var xh_clintonダxh_clintonダ_${index} = "deadcode"; // xh_clintonダ\n`;
        }
    });
    
    finalCode += `// xh_clintonダ Obfuscation Complete\n`;
    finalCode += `// Protected by xh_clintonダ - ${new Date().toLocaleString()}\n`;
    return finalCode;
}

// Deobfuscate JavaScript
function deobfuscateCode(content) {
    let cleanedCode = content.replace(/\/\/.*xh_clintonダ.*\n/g, '');
    cleanedCode = cleanedCode.replace(/var xh_clintonダxh_clintonダ_\d+ = "deadcode";.*\n/g, '');
    cleanedCode = cleanedCode.replace(/xh_clintonダxh_clintonダ_/g, '_v');
    cleanedCode = cleanedCode.replace(/\\x([0-9A-Fa-f]{2})/g, (match, p1) => String.fromCharCode(parseInt(p1, 16)));
    
    const beautifiedCode = beautify(cleanedCode, {
        indent_size: 2,
        space_in_paren: true,
        jslint_happy: true
    });
    
    return `// Deobfuscated by xh_clintonダ\n${beautifiedCode}\n// Deobfuscation by xh_clintonダ - ${new Date().toLocaleString()}`;
}

// Obfuscate Document
function obfuscateDocument(buffer, filename) {
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(SECRET_KEY, salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    const output = Buffer.concat([
        Buffer.from('xh_clintonダ_ENCDOC_'),
        salt,
        iv,
        Buffer.from(filename + '||'),
        encrypted
    ]);
    
    return output;
}

// Deobfuscate Document
function deobfuscateDocument(buffer) {
    if (!buffer.toString().startsWith('xh_clintonダ_ENCDOC_')) {
        throw new Error('Not a valid xh_clintonダ obfuscated document');
    }
    
    const markerLength = 'xh_clintonダ_ENCDOC_'.length;
    const salt = buffer.slice(markerLength, markerLength + 16);
    const iv = buffer.slice(markerLength + 16, markerLength + 32);
    const filenameEnd = buffer.indexOf('||', markerLength + 32);
    const filename = buffer.slice(markerLength + 32, filenameEnd).toString();
    const encrypted = buffer.slice(filenameEnd + 2);
    
    const key = crypto.pbkdf2Sync(SECRET_KEY, salt, 100000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return { decrypted, filename };
}

// Welcome/Help message
const welcomeMessage = `
│❒ *What’s up? Time to make things happen! ⚡*
│❒ Welcome to xh_clintonダ Obfuscator Bot 😼
│❒ Secure your JavaScript code or word documents with ease!

💾 *Database*: None
📚 *Library*: Telegraf
│❒ *Credits*: xh_clinton

📜 *Services Menu*:
🔹 *JavaScript (.js)*:
  - Obfuscate: /enc or /encrypt (or button)
  - Deobfuscate: /dec or /decrypt (or button)
🔹 *Documents (.doc, .docx, .odt, .rtf, .txt, etc.)*:
  - Obfuscate: /encdoc or /encryptdoc (or button)
  - Deobfuscate: /decdoc or /decryptdoc (or button)

📋 *How to Use*:
1. Send a .js or document file.
2. Use the buttons (Obfuscate/Deobfuscate) or reply with a command.
3. Get your secure or restored file!
`;

bot.command(['start', 'help'], async (ctx) => {
    const loading = await showLoading(ctx, 'Starting xh_clintonダ Bot');
    setTimeout(async () => {
        loading.stop();
        await ctx.replyWithPhoto({ url: logoUrl }, {
            caption: formatMessage(welcomeMessage)
        });
    }, 2000);
});

// Document handler sctn
bot.on('document', async (ctx) => {
    const file = ctx.message.document;
    const fileName = file.file_name.toLowerCase();
    const isJs = fileName.endsWith('.js');
    const isDoc = SUPPORTED_DOC_EXTENSIONS.some(ext => fileName.endsWith(ext));
    
    if (!isJs && !isDoc) {
        return ctx.reply(formatMessage('❌ Please provide a JavaScript file (.js) or a word document (.doc, .docx, .odt, .rtf, .txt, etc.).'));
    }
    
    await ctx.reply(
        formatMessage(`✅ ${isJs ? 'JavaScript' : 'Document'} file received! Select an action:`),
        Markup.inlineKeyboard([
            [Markup.button.callback('Obfuscate', isJs ? 'obfuscate_js' : 'obfuscate_doc')],
            [Markup.button.callback('Deobfuscate', isJs ? 'deobfuscate_js' : 'deobfuscate_doc')]
        ])
    );
});

// Action handler for buttons
bot.action(['obfuscate_js', 'deobfuscate_js', 'obfuscate_doc', 'deobfuscate_doc'], async (ctx) => {
    const action = ctx.match[0];
    const message = ctx.callbackQuery.message.reply_to_message || ctx.callbackQuery.message;
    if (!message || !message.document) {
        return ctx.reply(formatMessage('❌ No document found to process.'));
    }
    
    const file = message.document;
    const fileName = file.file_name.toLowerCase();
    
    try {
        const loading = await showLoading(ctx, `Processing xh_clintonダ (${action.includes('obfuscate') ? 'Obfuscating' : 'Deobfuscating'})`);
        const fileLink = await ctx.telegram.getFileLink(file.file_id);
        const response = await fetch(fileLink);
        const buffer = await response.buffer();
        
        let outputFilename, outputContent;
        
        if (action === 'obfuscate_js' && fileName.endsWith('.js')) {
            const fileContent = buffer.toString();
            outputContent = obfuscateCode(fileContent);
            outputFilename = `obfuscated_${file.file_name}`;
        } else if (action === 'deobfuscate_js' && fileName.endsWith('.js')) {
            const fileContent = buffer.toString();
            outputContent = deobfuscateCode(fileContent);
            outputFilename = `deobfuscated_${file.file_name}`;
        } else if (action === 'obfuscate_doc' && SUPPORTED_DOC_EXTENSIONS.some(ext => fileName.endsWith(ext))) {
            outputContent = obfuscateDocument(buffer, file.file_name);
            outputFilename = `obfuscated_${file.file_name}.bin`;
        } else if (action === 'deobfuscate_doc' && fileName.endsWith('.bin')) {
            const { decrypted, filename } = deobfuscateDocument(buffer);
            outputContent = decrypted;
            outputFilename = `deobfuscated_${filename}`;
        } else {
            loading.stop();
            return ctx.reply(formatMessage('❌ Invalid file type for this action.'));
        }
        
        fs.writeFileSync(outputFilename, outputContent);
        
        loading.stop();
        await ctx.replyWithDocument({
            source: fs.createReadStream(outputFilename),
            filename: outputFilename
        }, {
            caption: formatMessage(`✅ ${action.includes('obfuscate') ? 'Obfuscation' : 'Deobfuscation'} done! 🔹 Secured by xh_clintonダ`)
        });
        
        fs.unlinkSync(outputFilename);
    } catch (error) {
        console.error('Error:', error);
        loading.stop();
        await ctx.reply(formatMessage(`❌ Error: ${error.message}`));
    }
});

// Encrypt JavaScript command
bot.command(['enc', 'encrypt'], async (ctx) => {
    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.document) {
        return ctx.reply(formatMessage('❌ Reply to a .js file with /enc or /encrypt to obfuscate.'));
    }
    
    const file = ctx.message.reply_to_message.document;
    if (!file.file_name.toLowerCase().endsWith('.js')) {
        return ctx.reply(formatMessage('❌ Replied file must be a .js file.'));
    }
    
    try {
        const loading = await showLoading(ctx, 'Obfuscating xh_clintonダ');
        const fileLink = await ctx.telegram.getFileLink(file.file_id);
        const response = await fetch(fileLink);
        const fileContent = await response.text();
        
        const obfuscatedCode = obfuscateCode(fileContent);
        const outputFilename = `obfuscated_${file.file_name}`;
        
        fs.writeFileSync(outputFilename, obfuscatedCode);
        
        loading.stop();
        await ctx.replyWithDocument({
            source: fs.createReadStream(outputFilename),
            filename: outputFilename
        }, {
            caption: formatMessage('✅ Obfuscation done! 🔹 Secured by xh_clintonダ')
        });
        
        fs.unlinkSync(outputFilename);
    } catch (error) {
        console.error('Error:', error);
        await ctx.reply(formatMessage(`❌ Error: ${error.message}`));
    }
});

// Decrypt JavaScript command
bot.command(['dec', 'decrypt'], async (ctx) => {
    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.document) {
        return ctx.reply(formatMessage('❌ Reply to a .js file with /dec or /decrypt to deobfuscate.'));
    }
    
    const file = ctx.message.reply_to_message.document;
    if (!file.file_name.toLowerCase().endsWith('.js')) {
        return ctx.reply(formatMessage('❌ Replied file must be a .js file.'));
    }
    
    try {
        const loading = await showLoading(ctx, 'Deobfuscating xh_clintonダ');
        const fileLink = await ctx.telegram.getFileLink(file.file_id);
        const response = await fetch(fileLink);
        const fileContent = await response.text();
        
        const deobfuscatedCode = deobfuscateCode(fileContent);
        const outputFilename = `deobfuscated_${file.file_name}`;
        
        fs.writeFileSync(outputFilename, deobfuscatedCode);
        
        loading.stop();
        await ctx.replyWithDocument({
            source: fs.createReadStream(outputFilename),
            filename: outputFilename
        }, {
            caption: formatMessage('✅ Deobfuscation done! 🔹 Processed by xh_clintonダ')
        });
        
        fs.unlinkSync(outputFilename);
    } catch (error) {
        console.error('Error:', error);
        await ctx.reply(formatMessage(`❌ Error: ${error.message}`));
    }
});

// Encrypt Document command
bot.command(['encdoc', 'encryptdoc'], async (ctx) => {
    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.document) {
        return ctx.reply(formatMessage('❌ Reply to a word document with /encdoc or /encryptdoc to obfuscate.'));
    }
    
    const file = ctx.message.reply_to_message.document;
    const fileName = file.file_name.toLowerCase();
    if (!SUPPORTED_DOC_EXTENSIONS.some(ext => fileName.endsWith(ext))) {
        return ctx.reply(formatMessage('❌ Replied file must be a word document (.doc, .docx, .odt, .rtf, .txt, etc.).'));
    }
    
    try {
        const loading = await showLoading(ctx, 'Obfuscating xh_clintonダ Document');
        const fileLink = await ctx.telegram.getFileLink(file.file_id);
        const response = await fetch(fileLink);
        const buffer = await response.buffer();
        
        const obfuscatedContent = obfuscateDocument(buffer, file.file_name);
        const outputFilename = `obfuscated_${file.file_name}.bin`;
        
        fs.writeFileSync(outputFilename, obfuscatedContent);
        
        loading.stop();
        await ctx.replyWithDocument({
            source: fs.createReadStream(outputFilename),
            filename: outputFilename
        }, {
            caption: formatMessage('✅ Document obfuscation done! 🔹 Secured by xh_clintonダ')
        });
        
        fs.unlinkSync(outputFilename);
    } catch (error) {
        console.error('Error:', error);
        await ctx.reply(formatMessage(`❌ Error: ${error.message}`));
    }
});

// Decrypt Document command
bot.command(['decdoc', 'decryptdoc'], async (ctx) => {
    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.document) {
        return ctx.reply(formatMessage('❌ Reply to a .bin file with /decdoc or /decryptdoc to deobfuscate.'));
    }
    
    const file = ctx.message.reply_to_message.document;
    if (!file.file_name.toLowerCase().endsWith('.bin')) {
        return ctx.reply(formatMessage('❌ Replied file must be a .bin file.'));
    }
    
    try {
        const loading = await showLoading(ctx, 'Deobfuscating xh_clintonダ Document');
        const fileLink = await ctx.telegram.getFileLink(file.file_id);
        const response = await fetch(fileLink);
        const buffer = await response.buffer();
        
        const { decrypted, filename } = deobfuscateDocument(buffer);
        const outputFilename = `deobfuscated_${filename}`;
        
        fs.writeFileSync(outputFilename, decrypted);
        
        loading.stop();
        await ctx.replyWithDocument({
            source: fs.createReadStream(outputFilename),
            filename: outputFilename
        }, {
            caption: formatMessage('✅ Document deobfuscation done! 🔹 Processed by xh_clintonダ')
        });
        
        fs.unlinkSync(outputFilename);
    } catch (error) {
        console.error('Error:', error);
        await ctx.reply(formatMessage(`❌ Error: ${error.message}`));
    }
});

// Start the bot
bot.launch()
    .then(() => console.log('🤖 Bot is running! Send /start to begin'))
    .catch(err => console.error('Bot failed to start:', err));

// Graceful shutdown
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));