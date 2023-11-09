// ignore_for_file: library_private_types_in_public_api

import 'package:appli_flutter/chat_app.dart';
import 'package:flutter/material.dart';

class ChatScreen extends StatefulWidget {
  final MessageService messageService;

  const ChatScreen({super.key, required this.messageService});

  @override
  _ChatScreenState createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final TextEditingController _textController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Simple Chat App'),
      ),
      body: Column(
        children: <Widget>[
          Expanded(
            child: ListView.builder(
              itemCount: widget.messageService.messages.length,
              itemBuilder: (context, index) {
                final message = widget.messageService.messages[index];
                return ListTile(
                  title: Text(message.text),
                  subtitle: message.isSent
                      ? const Text('Sent')
                      : const Text('Received'),
                );
              },
            ),
          ),
          _buildMessageComposer(),
        ],
      ),
    );
  }

  Widget _buildMessageComposer() {
    return Padding(
      padding: const EdgeInsets.all(8.0),
      child: Row(
        children: <Widget>[
          Expanded(
            child: TextField(
              controller: _textController,
              decoration: const InputDecoration(
                hintText: 'Enter your message...',
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.send),
            onPressed: () {
              _sendMessage();
            },
          ),
        ],
      ),
    );
  }

  void _sendMessage() {
    final text = _textController.text;
    if (text.isNotEmpty) {
      final newMessage = Message(text, true);
      widget.messageService.addMessage(newMessage);
      _textController.clear();
    }
  }
}
