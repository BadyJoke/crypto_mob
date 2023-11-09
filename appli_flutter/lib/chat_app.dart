import 'package:appli_flutter/chat_screen.dart';
import 'package:flutter/material.dart';

void main() => runApp(MyApp());

class Message {
  final String text;
  final bool isSent;

  Message(this.text, this.isSent);
}

class MessageService {
  List<Message> messages = [];

  void addMessage(Message message) {
    messages.add(message);
  }
}

class MyApp extends StatelessWidget {
  final MessageService messageService = MessageService();

  MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: ChatScreen(messageService: messageService),
    );
  }
}
